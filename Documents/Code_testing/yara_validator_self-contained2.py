#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CI/CD-Enhanced YARA Rule Validator with Multi-Rule File Support

This script validates YARA rules and outputs them in formats suitable for CI/CD pipelines.
It can parse multiple rules from a single file and validate each independently.
It separates valid rules from broken ones and provides structured reports.

Usage:
    python validate_yara_rules.py <directory_path> [options]

Examples:
    python validate_yara_rules.py ./rules --output-valid-dir validated/ --output-failed-dir failed/
    python validate_yara_rules.py ./rules --output-valid-dir validated/ --json-report report.json
"""

import argparse
import os
import sys
import glob
import tempfile
import shutil
import re
import json
from pathlib import Path
from datetime import datetime

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed. Install it with: pip install yara-python", file=sys.stderr)
    sys.exit(1)


class YaraRule:
    """Represents a single YARA rule with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    STATUS_REPAIRED = 'repaired'
    
    def __init__(self, source, namespace='', include_name='', path='', rule_name='', imports=''):
        self.source = source
        self.namespace = namespace
        self.include_name = include_name
        self.path = path
        self.rule_name = rule_name  # Extracted rule name
        self.imports = imports  # Global imports to prepend
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_source = None
    
    def get_full_source(self):
        """Get complete source including imports."""
        if self.imports:
            return f"{self.imports}\n\n{self.source}"
        return self.source
    
    def to_dict(self):
        """Convert rule to dictionary for JSON serialization."""
        return {
            'path': self.path,
            'include_name': self.include_name,
            'rule_name': self.rule_name,
            'namespace': self.namespace,
            'status': self.status,
            'error': self.error_data,
            'has_repair': self.repaired_source is not None
        }
    
    def __str__(self):
        return self.source
    
    def __repr__(self):
        return f"<YaraRule {self.rule_name} - {self.status}>"


def extract_rule_name(rule_source):
    """Extract the rule name from rule source code."""
    match = re.search(r'^\s*rule\s+(\w+)', rule_source, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown_rule"


def count_braces_in_context(text):
    """
    Count braces while ignoring those in strings, comments, and hex patterns.
    Returns (open_count, close_count)
    """
    # Remove single-line comments
    text_no_single_comments = re.sub(r'//.*?$', '', text, flags=re.MULTILINE)
    
    # Remove multi-line comments
    text_no_comments = re.sub(r'/\*.*?\*/', '', text_no_single_comments, flags=re.DOTALL)
    
    # Remove quoted strings (both single and double quotes)
    # This handles escaped quotes as well
    text_no_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text_no_comments)
    text_no_strings = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text_no_strings)
    
    # Remove hex patterns like { 4D 5A 90 00 }
    # Hex patterns are sequences of hex digits (00-FF) with optional wildcards (?)
    text_no_hex = re.sub(r'\{\s*(?:[0-9A-Fa-f?]{2}\s*)+\}', '', text_no_strings)
    
    # Now count braces
    open_braces = text_no_hex.count('{')
    close_braces = text_no_hex.count('}')
    
    return open_braces, close_braces


def parse_yara_file(filepath):
    """
    Parse a YARA file and extract individual rules with their imports.
    
    Returns:
        tuple: (imports_string, list_of_rule_sources)
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        return "", []
    
    # Extract all import statements from the top of the file
    import_lines = []
    lines = content.split('\n')
    
    for line in lines:
        stripped = line.strip()
        # Check if line is an import statement
        if re.match(r'^\s*import\s+"[^"]+"\s*$', line):
            import_lines.append(line)
        elif stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
            # Stop at first non-import, non-comment, non-empty line
            if not re.match(r'^\s*import\s+"[^"]+"\s*$', stripped):
                break
    
    imports_string = '\n'.join(import_lines) if import_lines else ""
    
    # Extract individual rules using regex
    # Match: rule RuleName { ... } (handling nested braces)
    rules = []
    
    # Find all rule definitions
    rule_pattern = r'(^\s*(?:private\s+|global\s+)?rule\s+\w+.*?^\})'
    matches = re.finditer(rule_pattern, content, re.MULTILINE | re.DOTALL)
    
    for match in matches:
        rule_source = match.group(1)
        # Clean up the rule source
        rule_source = rule_source.strip()
        
        # Verify it's a complete rule by counting braces IN CONTEXT
        open_braces, close_braces = count_braces_in_context(rule_source)
        
        if open_braces == close_braces:
            rules.append(rule_source)
        elif open_braces > close_braces:
            # Only add closing braces if truly needed
            # This should rarely happen with proper regex matching
            missing_braces = open_braces - close_braces
            rule_source += '\n' + '}' * missing_braces
            rules.append(rule_source)
        # If close_braces > open_braces, something is wrong - skip this rule
    
    # If no rules found with the pattern, treat entire file as one rule
    if not rules:
        # Remove imports from content to get just the rule
        content_without_imports = content
        for import_line in import_lines:
            content_without_imports = content_without_imports.replace(import_line, '', 1)
        content_without_imports = content_without_imports.strip()
        
        if content_without_imports:
            rules.append(content_without_imports)
    
    return imports_string, rules


class YaraValidator:
    """Validates YARA rules with repair capabilities."""
    
    def __init__(self, auto_clear=True):
        self.rules = []
        self.auto_clear = auto_clear
        self.tmp_dir = tempfile.mkdtemp(prefix='yara_validator_')
        self.include_map = {}
    
    def add_rule_source(self, source, namespace='', include_name='', rule_name='', imports=''):
        """Add a YARA rule from source string."""
        if not rule_name:
            rule_name = extract_rule_name(source)
        
        rule = YaraRule(source, namespace, include_name, '', rule_name, imports)
        self.rules.append(rule)
        if include_name:
            self.include_map[include_name] = rule
    
    def add_rule_file(self, filepath, namespace='', include_name=''):
        """Add YARA rules from file, parsing multiple rules if present."""
        try:
            if not include_name:
                include_name = os.path.basename(filepath)
            if not namespace:
                namespace = os.path.dirname(filepath)
            
            # Parse file to extract imports and individual rules
            imports, rule_sources = parse_yara_file(filepath)
            
            if not rule_sources:
                print(f"  ⚠️  No rules found in {filepath}", file=sys.stderr)
                return
            
            # Create a YaraRule object for each parsed rule
            for rule_source in rule_sources:
                rule_name = extract_rule_name(rule_source)
                
                # Create unique include name if multiple rules in file
                if len(rule_sources) > 1:
                    rule_include_name = f"{include_name}::{rule_name}"
                else:
                    rule_include_name = include_name
                
                rule = YaraRule(
                    source=rule_source,
                    namespace=namespace,
                    include_name=rule_include_name,
                    path=filepath,
                    rule_name=rule_name,
                    imports=imports
                )
                self.rules.append(rule)
                self.include_map[rule_include_name] = rule
                
        except Exception as e:
            print(f"Error processing file {filepath}: {e}", file=sys.stderr)
    
    def _attempt_repair(self, source, imports=''):
        """Attempt to repair common YARA rule issues."""
        repaired = source
        repairs = []
        
        # Fix missing "condition:" keyword
        if 'condition' not in repaired and '{' in repaired:
            repaired = re.sub(
                r'(\{[^}]*?)(true|false|and|or|[0-9]+)',
                r'\1condition: \2',
                repaired
            )
            if repaired != source:
                repairs.append("Added missing 'condition:' keyword")
        
        # Fix missing braces - use context-aware counting
        open_braces, close_braces = count_braces_in_context(repaired)
        if open_braces != close_braces:
            if open_braces > close_braces:
                repaired += '\n}'
                repairs.append("Added missing closing brace")
        
        # Fix missing rule name
        if not re.search(r'rule\s+\w+\s*\{', repaired):
            if 'rule' in repaired and '{' in repaired:
                repaired = re.sub(r'rule\s*\{', 'rule DefaultRule {', repaired)
                repairs.append("Added missing rule name")
        
        return repaired, repairs
    
    def _validate_rule(self, rule, accept_repairs=False):
        """Validate a single rule."""
        try:
            # Try to compile the rule with imports
            full_source = rule.get_full_source()
            yara.compile(source=full_source)
            rule.status = YaraRule.STATUS_VALID
            return True
        except yara.Error as e:
            rule.error_data = str(e)
            
            # Try to repair
            if accept_repairs:
                repaired_source, repairs = self._attempt_repair(rule.source, rule.imports)
                if repaired_source != rule.source:
                    try:
                        # Test with imports
                        full_repaired = f"{rule.imports}\n\n{repaired_source}" if rule.imports else repaired_source
                        yara.compile(source=full_repaired)
                        rule.status = YaraRule.STATUS_REPAIRED
                        rule.repaired_source = repaired_source
                        rule.error_data = f"Repaired: {', '.join(repairs)}"
                        return True
                    except yara.Error:
                        pass
            
            rule.status = YaraRule.STATUS_BROKEN
            return False
    
    def check_all(self, accept_repairs=False):
        """Validate all rules and return categorized lists."""
        valid = []
        broken = []
        repaired = []
        
        for rule in self.rules:
            self._validate_rule(rule, accept_repairs)
            
            if rule.status == YaraRule.STATUS_VALID:
                valid.append(rule)
            elif rule.status == YaraRule.STATUS_REPAIRED:
                repaired.append(rule)
            else:
                broken.append(rule)
        
        return valid, broken, repaired
    
    def clear_tmp(self):
        """Clean up temporary directory."""
        try:
            if os.path.exists(self.tmp_dir):
                shutil.rmtree(self.tmp_dir)
        except Exception as e:
            print(f"Warning: Could not clear temp directory: {e}", file=sys.stderr)
    
    def __del__(self):
        if self.auto_clear:
            self.clear_tmp()


def collect_yara_files(directory, extensions=None):
    """Collect all YARA rule files from a directory."""
    if extensions is None:
        extensions = ['.yar', '.yara', '.rule']
    
    yara_files = []
    for ext in extensions:
        pattern = os.path.join(directory, '**', f'*{ext}')
        yara_files.extend(glob.glob(pattern, recursive=True))
    
    return sorted(set(yara_files))


def write_rules_to_directory(rules, output_dir, use_repaired=False):
    """Write rules to an output directory using rule names as filenames."""
    os.makedirs(output_dir, exist_ok=True)
    
    written_files = []
    rule_name_counts = {}  # Track duplicate rule names
    
    for rule in rules:
        # Use rule name for filename
        base_filename = rule.rule_name if rule.rule_name else "unknown_rule"
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Write the rule source with imports
        source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
        
        # Include imports in the output
        full_source = f"{rule.imports}\n\n{source_to_write}" if rule.imports else source_to_write
        
        # Add header comment
        header = f"// Rule: {rule.rule_name}\n"
        if rule.path:
            header += f"// Source: {rule.path}\n"
        header += f"// Validated: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_rules_to_directory(rules, output_dir):
    """Write failed rules to directory with error information."""
    os.makedirs(output_dir, exist_ok=True)
    
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name if rule.rule_name else "unknown_rule"
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Include imports in the output
        full_source = f"{rule.imports}\n\n{rule.source}" if rule.imports else rule.source
        
        # Add header with error information
        header = f"// VALIDATION FAILED\n"
        header += f"// Rule: {rule.rule_name}\n"
        if rule.path:
            header += f"// Source: {rule.path}\n"
        header += f"// Error: {rule.error_data}\n"
        header += f"// Timestamp: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_combined_rules(rules, output_file, use_repaired=False):
    """Write all rules to a single combined file."""
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    
    # Collect all unique imports
    all_imports = set()
    for rule in rules:
        if rule.imports:
            for import_line in rule.imports.split('\n'):
                if import_line.strip():
                    all_imports.add(import_line.strip())
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"// Combined YARA Rules\n")
        f.write(f"// Generated: {datetime.now().isoformat()}\n")
        f.write(f"// Total rules: {len(rules)}\n\n")
        
        # Write imports at the top
        if all_imports:
            f.write("// Global Imports\n")
            for import_stmt in sorted(all_imports):
                f.write(f"{import_stmt}\n")
            f.write("\n")
        
        # Write rules
        for rule in rules:
            source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
            
            f.write(f"// Rule: {rule.rule_name}\n")
            f.write(f"// Source: {rule.path if rule.path else 'inline'}\n")
            f.write(source_to_write)
            f.write("\n\n")


def generate_json_report(valid, broken, repaired, output_file):
    """Generate a JSON report of validation results."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total': len(valid) + len(broken) + len(repaired),
            'valid': len(valid),
            'broken': len(broken),
            'repaired': len(repaired),
            'success_rate': round((len(valid) + len(repaired)) / (len(valid) + len(broken) + len(repaired)) * 100, 2) if (len(valid) + len(broken) + len(repaired)) > 0 else 0
        },
        'valid_rules': [rule.to_dict() for rule in valid],
        'broken_rules': [rule.to_dict() for rule in broken],
        'repaired_rules': [rule.to_dict() for rule in repaired]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_markdown_report(valid, broken, repaired, output_file):
    """Generate a Markdown report for GitLab/GitHub."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA Rule Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary
        total = len(valid) + len(broken) + len(repaired)
        success_rate = round((len(valid) + len(repaired)) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Rules | {total} |\n")
        f.write(f"| ✅ Valid Rules | {len(valid)} |\n")
        f.write(f"| ❌ Broken Rules | {len(broken)} |\n")
        f.write(f"| 🔧 Repaired Rules | {len(repaired)} |\n")
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status badge
        if len(broken) == 0:
            f.write("**Status:** ✅ All rules validated successfully\n\n")
        else:
            f.write(f"**Status:** ⚠️ {len(broken)} rule(s) failed validation\n\n")
        
        # Valid rules
        if valid:
            f.write("## ✅ Valid Rules\n\n")
            for rule in valid:
                source_file = rule.path if rule.path else "inline"
                f.write(f"- **{rule.rule_name}** (`{source_file}`)\n")
            f.write("\n")
        
        # Repaired rules
        if repaired:
            f.write("## 🔧 Repaired Rules\n\n")
            for rule in repaired:
                source_file = rule.path if rule.path else "inline"
                f.write(f"### **{rule.rule_name}** (`{source_file}`)\n\n")
                f.write(f"**Repair Applied:** {rule.error_data}\n\n")
                f.write("<details>\n")
                f.write("<summary>View repaired source</summary>\n\n")
                f.write("```yara\n")
                # Show repaired source with imports
                full_source = f"{rule.imports}\n\n{rule.repaired_source}" if rule.imports and rule.repaired_source else (rule.repaired_source or "")
                lines = full_source.split('\n')
                for line in lines[:30]:
                    f.write(f"{line}\n")
                if len(lines) > 30:
                    f.write(f"... ({len(lines) - 30} more lines)\n")
                f.write("```\n")
                f.write("</details>\n\n")
            f.write("\n")
        
        # Broken rules with detailed error information
        if broken:
            f.write("## ❌ Broken Rules - Detailed Error Report\n\n")
            for i, rule in enumerate(broken, 1):
                source_file = rule.path if rule.path else "inline"
                f.write(f"### {i}. **{rule.rule_name}** (`{source_file}`)\n\n")
                
                # Error message
                f.write(f"**Validation Error:**\n")
                f.write("```\n")
                f.write(f"{rule.error_data}\n")
                f.write("```\n\n")
                
                # Parse error for line number if available
                line_match = re.search(r'line (\d+)', rule.error_data)
                error_line = int(line_match.group(1)) if line_match else None
                
                # Show rule source with context
                f.write("<details>\n")
                f.write("<summary>View rule source</summary>\n\n")
                f.write("```yara\n")
                
                # Get full source with imports
                full_source = rule.get_full_source()
                lines = full_source.split('\n')
                
                # If we know the error line, show context around it
                if error_line and error_line <= len(lines):
                    start = max(0, error_line - 10)
                    end = min(len(lines), error_line + 10)
                    
                    for line_num in range(start, end):
                        line = lines[line_num]
                        # Mark the error line
                        if line_num + 1 == error_line:
                            f.write(f"{line_num + 1:4d}: >>> {line} <<<  ⚠️ ERROR HERE\n")
                        else:
                            f.write(f"{line_num + 1:4d}: {line}\n")
                    
                    if end < len(lines):
                        f.write(f"... ({len(lines) - end} more lines)\n")
                else:
                    # Show first 30 lines if no specific error line
                    for line_num, line in enumerate(lines[:30], 1):
                        f.write(f"{line_num:4d}: {line}\n")
                    if len(lines) > 30:
                        f.write(f"... ({len(lines) - 30} more lines)\n")
                
                f.write("```\n")
                f.write("</details>\n\n")
                
                # Possible fix suggestions
                if "syntax error" in rule.error_data.lower():
                    f.write("**💡 Possible fixes:**\n")
                    f.write("- Check for missing or extra braces `{}`\n")
                    f.write("- Verify the `condition:` section syntax\n")
                    f.write("- Ensure all strings in `strings:` section are properly formatted\n")
                    f.write("- Check for missing colons after `meta:`, `strings:`, or `condition:`\n\n")
                elif "undefined" in rule.error_data.lower():
                    f.write("**💡 Possible fixes:**\n")
                    f.write("- Check that all variables referenced in condition are defined in strings section\n")
                    f.write("- Verify spelling of variable names\n")
                    f.write("- Ensure required imports are present (e.g., `import \"pe\"` for PE module functions)\n\n")
                elif "duplicated" in rule.error_data.lower():
                    f.write("**💡 Possible fixes:**\n")
                    f.write("- Rename duplicate rule or identifier\n")
                    f.write("- Check for conflicting imports\n\n")
                
                f.write("---\n\n")


def validate_directory_cicd(directory, accept_repairs=False, verbose=False,
                            output_valid_dir=None, output_valid_combined=None,
                            output_failed_dir=None, json_report=None,
                            markdown_report=None, namespace=None):
    """Validate YARA rules with CI/CD-friendly outputs."""
    
    print("="*80)
    print("YARA Rule Validation for CI/CD (Multi-Rule File Support)")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    print("="*80)
    
    # Collect YARA files
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    # Initialize validator
    validator = YaraValidator(auto_clear=False)
    
    # Add all rule files (this will parse multiple rules per file)
    print("\n📥 Loading and parsing rules...")
    total_rules_loaded = 0
    for yara_file in yara_files:
        try:
            include_name = os.path.basename(yara_file)
            rule_namespace = namespace if namespace else os.path.dirname(yara_file)
            
            rules_before = len(validator.rules)
            validator.add_rule_file(yara_file, namespace=rule_namespace, include_name=include_name)
            rules_after = len(validator.rules)
            rules_in_file = rules_after - rules_before
            
            total_rules_loaded += rules_in_file
            
            if verbose:
                print(f"  ✓ Loaded {rules_in_file} rule(s) from: {yara_file}")
        except Exception as e:
            print(f"  ✗ Error loading {yara_file}: {e}")
    
    print(f"\n📊 Total rules parsed: {total_rules_loaded}")
    
    # Validate all rules
    print("\n🔍 Validating rules...")
    valid, broken, repaired = validator.check_all(accept_repairs=accept_repairs)
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid rules:    {len(valid)}")
    print(f"❌ Broken rules:   {len(broken)}")
    print(f"🔧 Repaired rules: {len(repaired)}")
    print("="*80)
    
    # Print detailed results if verbose
    if verbose:
        if valid:
            print(f"\n{'='*25} VALID RULES ({len(valid)}) {'='*25}")
            for rule in valid:
                source_info = f"{rule.path} -> {rule.rule_name}" if rule.path else rule.rule_name
                print(f"  ✓ {source_info}")
        
        if repaired:
            print(f"\n{'='*25} REPAIRED RULES ({len(repaired)}) {'='*25}")
            for rule in repaired:
                source_info = f"{rule.path} -> {rule.rule_name}" if rule.path else rule.rule_name
                print(f"  🔧 {source_info}")
                print(f"     Repair: {rule.error_data}")
        
        if broken:
            print(f"\n{'='*25} BROKEN RULES ({len(broken)}) {'='*25}")
            for rule in broken:
                source_info = f"{rule.path} -> {rule.rule_name}" if rule.path else rule.rule_name
                print(f"  ❌ {source_info}")
                print(f"     Error: {rule.error_data}")
                # Show first few lines of the rule for context
                lines = rule.source.split('\n')
                print(f"     Source preview (first 5 lines):")
                for i, line in enumerate(lines[:5], 1):
                    print(f"       {i:2d}: {line}")
                if len(lines) > 5:
                    print(f"       ... ({len(lines) - 5} more lines)")
                print()
    
    # Write outputs
    if output_valid_dir:
        print(f"\n📝 Writing valid rules to directory: {output_valid_dir}")
        written = write_rules_to_directory(valid, output_valid_dir, use_repaired=False)
        print(f"   Wrote {len(written)} file(s)")
        
        if repaired:
            print(f"\n📝 Writing repaired rules to directory: {output_valid_dir}")
            written_repaired = write_rules_to_directory(repaired, output_valid_dir, use_repaired=True)
            print(f"   Wrote {len(written_repaired)} repaired file(s)")
    
    if output_valid_combined:
        print(f"\n📝 Writing combined valid rules to: {output_valid_combined}")
        all_valid = valid + repaired
        write_combined_rules(all_valid, output_valid_combined, use_repaired=True)
        print(f"   Wrote {len(all_valid)} rule(s)")
    
    if output_failed_dir and broken:
        print(f"\n📝 Writing failed rules to directory: {output_failed_dir}")
        written = write_failed_rules_to_directory(broken, output_failed_dir)
        print(f"   Wrote {len(written)} file(s) with error information")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        report_data = generate_json_report(valid, broken, repaired, json_report)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        generate_markdown_report(valid, broken, repaired, markdown_report)
    
    # Cleanup
    validator.clear_tmp()
    
    print("\n" + "="*80)
    if broken:
        print(f"⚠️  Validation completed with {len(broken)} failure(s)")
    else:
        print("✅ Validation completed successfully!")
    print("="*80)
    
    return len(valid), len(broken), len(repaired)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Validate YARA rules for CI/CD pipelines (supports multi-rule files)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./rules --output-valid-dir validated/
  %(prog)s ./rules --output-valid-combined validated_rules.yar
  %(prog)s ./rules --output-valid-dir validated/ --output-failed-dir failed/
  %(prog)s ./rules --json-report report.json --markdown-report report.md
  
Features:
  - Parses multiple rules from single files
  - Preserves and applies global import statements
  - Outputs each rule as individual file named by rule name
  - Validates each rule independently
        """
    )
    
    parser.add_argument('directory', help='Directory containing YARA rule files')
    parser.add_argument('--accept-repairs', action='store_true', 
                       help='Attempt to repair broken rules')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Show detailed output')
    parser.add_argument('--output-valid-dir', metavar='DIR',
                       help='Output directory for valid rules (one file per rule)')
    parser.add_argument('--output-valid-combined', metavar='FILE',
                       help='Output file for combined valid rules')
    parser.add_argument('--output-failed-dir', metavar='DIR',
                       help='Output directory for failed rules (one file per rule with error info)')
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    parser.add_argument('--markdown-report', metavar='FILE',
                       help='Generate Markdown report')
    parser.add_argument('--namespace', '-n', metavar='NAME',
                       help='Namespace for all rules')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"❌ Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    try:
        valid_count, broken_count, repaired_count = validate_directory_cicd(
            args.directory,
            accept_repairs=args.accept_repairs,
            verbose=args.verbose,
            output_valid_dir=args.output_valid_dir,
            output_valid_combined=args.output_valid_combined,
            output_failed_dir=args.output_failed_dir,
            json_report=args.json_report,
            markdown_report=args.markdown_report,
            namespace=args.namespace
        )
        
        # Exit with appropriate code
        # 0 = success (all rules valid or repaired)
        # 1 = validation failures
        # 2 = no rules found or error
        if valid_count == 0 and repaired_count == 0:
            sys.exit(2)
        elif broken_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"❌ Error during validation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
