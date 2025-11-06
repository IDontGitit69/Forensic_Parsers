#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
YARA Rule Validator for CI/CD Pipelines

This script validates YARA rule files with two operation modes:

1. FILE MODE (Default): Validates entire files as-is, preserving all rules, imports, 
   and dependencies together. This is the recommended mode for most use cases.

2. SPLIT MODE (--split-rules): Parses individual rules from files and validates each 
   separately. Useful for isolating issues in multi-rule files.

Usage:
    # Validate entire files (recommended)
    python validate_yara_rules.py <directory> --output-valid-dir validated/
    
    # Split and validate individual rules
    python validate_yara_rules.py <directory> --split-rules --output-valid-dir validated/

Examples:
    # File mode: Validate complete files
    python validate_yara_rules.py ./rules --output-valid-dir validated/
    
    # File mode: With failed files output
    python validate_yara_rules.py ./rules --output-valid-dir validated/ --output-failed-dir failed/
    
    # Split mode: Parse and validate individual rules
    python validate_yara_rules.py ./rules --split-rules --output-valid-dir validated/
    
    # Generate reports
    python validate_yara_rules.py ./rules --json-report report.json --markdown-report report.md
"""

import argparse
import os
import sys
import glob
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


# ============================================================================
# YARA FILE REPRESENTATION
# ============================================================================

class YaraFile:
    """Represents a complete YARA file with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    
    def __init__(self, filepath, content=None):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.content = content
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.rule_count = 0
    
    def load_content(self):
        """Load file content if not already loaded."""
        if self.content is None:
            try:
                with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    self.content = f.read()
            except Exception as e:
                raise IOError(f"Failed to read {self.filepath}: {e}")
        return self.content
    
    def count_rules(self):
        """Count the number of rules in the file."""
        if self.content:
            rule_pattern = re.compile(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+\w+', re.MULTILINE)
            self.rule_count = len(rule_pattern.findall(self.content))
        return self.rule_count
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'filepath': self.filepath,
            'filename': self.filename,
            'status': self.status,
            'rule_count': self.rule_count,
            'error': self.error_data
        }
    
    def __repr__(self):
        return f"<YaraFile {self.filename} - {self.status} - {self.rule_count} rules>"


class YaraRule:
    """Represents a single YARA rule with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    
    def __init__(self, source, source_file='', rule_name='', imports=''):
        self.source = source
        self.source_file = source_file
        self.rule_name = rule_name or self._extract_name()
        self.imports = imports
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
    
    def _extract_name(self):
        """Extract the rule name from source code."""
        match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', self.source, re.MULTILINE)
        return match.group(1) if match else "unknown_rule"
    
    def get_full_source(self):
        """Get complete source including imports."""
        if self.imports:
            return f"{self.imports}\n\n{self.source}"
        return self.source
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'source_file': self.source_file,
            'rule_name': self.rule_name,
            'status': self.status,
            'error': self.error_data
        }
    
    def __repr__(self):
        return f"<YaraRule {self.rule_name} - {self.status}>"


# ============================================================================
# RULE PARSING UTILITIES
# ============================================================================

def parse_yara_file_to_rules(filepath):
    """
    Parse a YARA file and extract individual rules with their imports.
    Uses simple line-by-line approach to detect rule boundaries.
    
    Returns:
        tuple: (imports_string, list_of_rule_sources)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        return "", []
    
    # Pattern to detect start of YARA rules (case-insensitive)
    rule_pattern = re.compile(r'(?i)^\s*(private\s+|global\s+)?rule\s+\w+')
    
    # Separate header (imports/comments) from rules
    header_lines = []
    rule_blocks = []
    current_rule = []
    in_rule = False
    
    for line in lines:
        # Check if this line starts a new rule
        if rule_pattern.match(line):
            # If we were building a rule, save it
            if current_rule:
                rule_blocks.append(current_rule)
            # Start a new rule
            current_rule = [line]
            in_rule = True
        else:
            # If we're not in a rule yet, this is part of the header
            if not in_rule:
                header_lines.append(line)
            else:
                # We're in a rule, add to current rule
                current_rule.append(line)
    
    # Don't forget the last rule
    if current_rule:
        rule_blocks.append(current_rule)
    
    # Extract imports from header
    import_lines = []
    for line in header_lines:
        if re.match(r'^\s*import\s+"[^"]+"\s*$', line):
            import_lines.append(line.rstrip())
    
    imports_string = '\n'.join(import_lines) if import_lines else ""
    
    # Convert rule blocks to strings
    rules = []
    for rule_block in rule_blocks:
        rule_text = ''.join(rule_block).strip()
        if rule_text:
            rules.append(rule_text)
    
    return imports_string, rules


# ============================================================================
# VALIDATORS
# ============================================================================

class FileValidator:
    """Validates complete YARA files."""
    
    def __init__(self):
        self.files = []
    
    def add_file(self, filepath):
        """Add a YARA file for validation."""
        yara_file = YaraFile(filepath)
        self.files.append(yara_file)
        return yara_file
    
    def validate_file(self, yara_file):
        """Validate a single YARA file."""
        try:
            # Load content
            content = yara_file.load_content()
            yara_file.count_rules()
            
            # Validate by compiling
            yara.compile(source=content)
            yara_file.status = YaraFile.STATUS_VALID
            return True
            
        except yara.Error as e:
            yara_file.status = YaraFile.STATUS_BROKEN
            yara_file.error_data = str(e)
            return False
        except Exception as e:
            yara_file.status = YaraFile.STATUS_BROKEN
            yara_file.error_data = f"Failed to process file: {str(e)}"
            return False
    
    def validate_all(self):
        """Validate all files and return categorized lists."""
        valid = []
        broken = []
        
        for yara_file in self.files:
            if self.validate_file(yara_file):
                valid.append(yara_file)
            else:
                broken.append(yara_file)
        
        return valid, broken


class RuleValidator:
    """Validates individual YARA rules (split mode)."""
    
    def __init__(self):
        self.rules = []
    
    def add_file(self, filepath):
        """Parse a file and add all its rules for validation."""
        imports, rule_sources = parse_yara_file_to_rules(filepath)
        
        for rule_source in rule_sources:
            rule = YaraRule(
                source=rule_source,
                source_file=filepath,
                imports=imports
            )
            self.rules.append(rule)
        
        return len(rule_sources)
    
    def validate_rule(self, rule):
        """Validate a single rule."""
        try:
            full_source = rule.get_full_source()
            yara.compile(source=full_source)
            rule.status = YaraRule.STATUS_VALID
            return True
        except yara.Error as e:
            rule.status = YaraRule.STATUS_BROKEN
            rule.error_data = str(e)
            return False
    
    def validate_all(self):
        """Validate all rules and return categorized lists."""
        valid = []
        broken = []
        
        for rule in self.rules:
            if self.validate_rule(rule):
                valid.append(rule)
            else:
                broken.append(rule)
        
        return valid, broken


# ============================================================================
# FILE I/O OPERATIONS
# ============================================================================

def collect_yara_files(directory, extensions=None):
    """Collect all YARA rule files from a directory."""
    if extensions is None:
        extensions = ['.yar', '.yara', '.rule']
    
    yara_files = []
    for ext in extensions:
        pattern = os.path.join(directory, '**', f'*{ext}')
        yara_files.extend(glob.glob(pattern, recursive=True))
    
    return sorted(set(yara_files))


def write_valid_files(yara_files, output_dir):
    """Write valid YARA files to output directory, preserving filenames."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        # Handle duplicate filenames
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
        # Add validation header
        header = f"// Validated: {datetime.now().isoformat()}\n"
        header += f"// Source: {yara_file.filepath}\n"
        header += f"// Rules: {yara_file.rule_count}\n"
        header += f"// Status: {yara_file.status.upper()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(yara_file.content)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_files(yara_files, output_dir):
    """Write failed YARA files to output directory with error info."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        # Handle duplicate filenames
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
        # Add error header
        header = f"// VALIDATION FAILED\n"
        header += f"// Source: {yara_file.filepath}\n"
        header += f"// Rules: {yara_file.rule_count}\n"
        header += f"// Error: {yara_file.error_data}\n"
        header += f"// Timestamp: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(yara_file.content)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_valid_rules(rules, output_dir):
    """Write valid rules to output directory as individual files."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Get full source with imports
        full_source = rule.get_full_source()
        
        # Add header
        header = f"// Rule: {rule.rule_name}\n"
        header += f"// Source: {rule.source_file}\n"
        header += f"// Validated: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_rules(rules, output_dir):
    """Write failed rules to output directory with error info."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Get full source with imports
        full_source = rule.get_full_source()
        
        # Add error header
        header = f"// VALIDATION FAILED\n"
        header += f"// Rule: {rule.rule_name}\n"
        header += f"// Source: {rule.source_file}\n"
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


# ============================================================================
# REPORTING
# ============================================================================

def generate_file_json_report(valid_files, broken_files, output_file):
    """Generate JSON report for file-level validation."""
    total = len(valid_files) + len(broken_files)
    total_rules = sum(f.rule_count for f in valid_files + broken_files)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'file',
        'summary': {
            'total_files': total,
            'valid_files': len(valid_files),
            'broken_files': len(broken_files),
            'total_rules': total_rules,
            'success_rate': round(len(valid_files) / total * 100, 2) if total > 0 else 0
        },
        'valid_files': [f.to_dict() for f in valid_files],
        'broken_files': [f.to_dict() for f in broken_files]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_rule_json_report(valid_rules, broken_rules, output_file):
    """Generate JSON report for rule-level validation."""
    total = len(valid_rules) + len(broken_rules)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'split',
        'summary': {
            'total_rules': total,
            'valid_rules': len(valid_rules),
            'broken_rules': len(broken_rules),
            'success_rate': round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        },
        'valid_rules': [r.to_dict() for r in valid_rules],
        'broken_rules': [r.to_dict() for r in broken_rules]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_file_markdown_report(valid_files, broken_files, output_file):
    """Generate Markdown report for file-level validation."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA File Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** File-level validation\n\n")
        
        # Summary
        total = len(valid_files) + len(broken_files)
        total_rules = sum(file.rule_count for file in valid_files + broken_files)
        success_rate = round(len(valid_files) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Files | {total} |\n")
        f.write(f"| ✅ Valid Files | {len(valid_files)} |\n")
        f.write(f"| ❌ Broken Files | {len(broken_files)} |\n")
        f.write(f"| Total Rules | {total_rules} |\n")
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_files) == 0:
            f.write("**Status:** ✅ All files validated successfully\n\n")
        else:
            f.write(f"**Status:** ⚠️ {len(broken_files)} file(s) failed validation\n\n")
        
        # Valid files
        if valid_files:
            f.write("## ✅ Valid Files\n\n")
            for file in valid_files:
                f.write(f"- **{file.filename}** ({file.rule_count} rule(s)) - `{file.filepath}`\n")
            f.write("\n")
        
        # Broken files
        if broken_files:
            f.write("## ❌ Broken Files\n\n")
            for i, file in enumerate(broken_files, 1):
                f.write(f"### {i}. {file.filename}\n\n")
                f.write(f"- **Path:** `{file.filepath}`\n")
                f.write(f"- **Rules:** {file.rule_count}\n")
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{file.error_data}\n")
                f.write("```\n\n")
                
                # Show first 20 lines of content
                if file.content:
                    f.write("<details>\n")
                    f.write("<summary>View file content (first 20 lines)</summary>\n\n")
                    f.write("```yara\n")
                    lines = file.content.split('\n')
                    for line_num, line in enumerate(lines[:20], 1):
                        f.write(f"{line_num:4d}: {line}\n")
                    if len(lines) > 20:
                        f.write(f"... ({len(lines) - 20} more lines)\n")
                    f.write("```\n")
                    f.write("</details>\n\n")
                
                f.write("---\n\n")


def generate_rule_markdown_report(valid_rules, broken_rules, output_file):
    """Generate Markdown report for rule-level validation."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA Rule Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** Split-rule validation\n\n")
        
        # Summary
        total = len(valid_rules) + len(broken_rules)
        success_rate = round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Rules | {total} |\n")
        f.write(f"| ✅ Valid Rules | {len(valid_rules)} |\n")
        f.write(f"| ❌ Broken Rules | {len(broken_rules)} |\n")
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_rules) == 0:
            f.write("**Status:** ✅ All rules validated successfully\n\n")
        else:
            f.write(f"**Status:** ⚠️ {len(broken_rules)} rule(s) failed validation\n\n")
        
        # Valid rules
        if valid_rules:
            f.write("## ✅ Valid Rules\n\n")
            for rule in valid_rules:
                f.write(f"- **{rule.rule_name}** - `{rule.source_file}`\n")
            f.write("\n")
        
        # Broken rules
        if broken_rules:
            f.write("## ❌ Broken Rules\n\n")
            for i, rule in enumerate(broken_rules, 1):
                f.write(f"### {i}. {rule.rule_name}\n\n")
                f.write(f"- **Source:** `{rule.source_file}`\n")
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{rule.error_data}\n")
                f.write("```\n\n")
                
                # Show rule source
                f.write("<details>\n")
                f.write("<summary>View rule source</summary>\n\n")
                f.write("```yara\n")
                full_source = rule.get_full_source()
                lines = full_source.split('\n')
                for line_num, line in enumerate(lines[:30], 1):
                    f.write(f"{line_num:4d}: {line}\n")
                if len(lines) > 30:
                    f.write(f"... ({len(lines) - 30} more lines)\n")
                f.write("```\n")
                f.write("</details>\n\n")
                
                f.write("---\n\n")


# ============================================================================
# MAIN VALIDATION WORKFLOWS
# ============================================================================

def validate_files_mode(directory, verbose=False, output_valid_dir=None, 
                       output_failed_dir=None, json_report=None, markdown_report=None):
    """Validate entire files (default mode)."""
    
    print("="*80)
    print("YARA File Validator - FILE MODE")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    print("="*80)
    
    # Collect files
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    # Initialize validator
    validator = FileValidator()
    
    # Add files
    print("\n📥 Loading files...")
    for filepath in yara_files:
        try:
            validator.add_file(filepath)
            if verbose:
                print(f"  ✓ Loaded: {filepath}")
        except Exception as e:
            print(f"  ✗ Error loading {filepath}: {e}")
    
    # Validate
    print("\n🔍 Validating files...")
    valid_files, broken_files = validator.validate_all()
    
    # Calculate total rules
    total_rules = sum(f.rule_count for f in valid_files + broken_files)
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid files:   {len(valid_files)}")
    print(f"❌ Broken files:  {len(broken_files)}")
    print(f"📊 Total rules:   {total_rules}")
    print("="*80)
    
    # Print details if verbose
    if verbose:
        if valid_files:
            print(f"\n{'='*25} VALID FILES ({len(valid_files)}) {'='*25}")
            for file in valid_files:
                print(f"  ✓ {file.filename} ({file.rule_count} rules)")
        
        if broken_files:
            print(f"\n{'='*25} BROKEN FILES ({len(broken_files)}) {'='*25}")
            for file in broken_files:
                print(f"  ❌ {file.filename} ({file.rule_count} rules)")
                print(f"     Error: {file.error_data[:100]}...")
                print()
    
    # Write outputs
    if output_valid_dir and valid_files:
        print(f"\n📝 Writing valid files to: {output_valid_dir}")
        written = write_valid_files(valid_files, output_valid_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if output_failed_dir and broken_files:
        print(f"\n📝 Writing failed files to: {output_failed_dir}")
        written = write_failed_files(broken_files, output_failed_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        generate_file_json_report(valid_files, broken_files, json_report)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        generate_file_markdown_report(valid_files, broken_files, markdown_report)
    
    print("\n" + "="*80)
    if broken_files:
        print(f"⚠️  Validation completed with {len(broken_files)} file failure(s)")
    else:
        print("✅ All files validated successfully!")
    print("="*80)
    
    return len(valid_files), len(broken_files)


def validate_split_mode(directory, verbose=False, output_valid_dir=None,
                       output_failed_dir=None, json_report=None, markdown_report=None):
    """Validate individual rules (split mode)."""
    
    print("="*80)
    print("YARA Rule Validator - SPLIT MODE")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    print("="*80)
    
    # Collect files
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    # Initialize validator
    validator = RuleValidator()
    
    # Parse and add rules
    print("\n📥 Parsing rules from files...")
    total_rules = 0
    for filepath in yara_files:
        try:
            rule_count = validator.add_file(filepath)
            total_rules += rule_count
            if verbose:
                print(f"  ✓ Parsed {rule_count} rule(s) from: {filepath}")
        except Exception as e:
            print(f"  ✗ Error parsing {filepath}: {e}")
    
    print(f"\n📊 Total rules parsed: {total_rules}")
    
    # Validate
    print("\n🔍 Validating rules...")
    valid_rules, broken_rules = validator.validate_all()
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid rules:   {len(valid_rules)}")
    print(f"❌ Broken rules:  {len(broken_rules)}")
    print("="*80)
    
    # Print details if verbose
    if verbose:
        if valid_rules:
            print(f"\n{'='*25} VALID RULES ({len(valid_rules)}) {'='*25}")
            for rule in valid_rules:
                print(f"  ✓ {rule.rule_name} <- {os.path.basename(rule.source_file)}")
        
        if broken_rules:
            print(f"\n{'='*25} BROKEN RULES ({len(broken_rules)}) {'='*25}")
            for rule in broken_rules:
                print(f"  ❌ {rule.rule_name} <- {os.path.basename(rule.source_file)}")
                print(f"     Error: {rule.error_data[:100]}...")
                print()
    
    # Write outputs
    if output_valid_dir and valid_rules:
        print(f"\n📝 Writing valid rules to: {output_valid_dir}")
        written = write_valid_rules(valid_rules, output_valid_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if output_failed_dir and broken_rules:
        print(f"\n📝 Writing failed rules to: {output_failed_dir}")
        written = write_failed_rules(broken_rules, output_failed_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        generate_rule_json_report(valid_rules, broken_rules, json_report)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        generate_rule_markdown_report(valid_rules, broken_rules, markdown_report)
    
    print("\n" + "="*80)
    if broken_rules:
        print(f"⚠️  Validation completed with {len(broken_rules)} rule failure(s)")
    else:
        print("✅ All rules validated successfully!")
    print("="*80)
    
    return len(valid_rules), len(broken_rules)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='YARA Rule Validator for CI/CD Pipelines',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
OPERATION MODES:

  FILE MODE (default):
    Validates entire files as-is, preserving all rules, imports, and dependencies.
    This is the recommended mode for most use cases.
    
    Example: python %(prog)s ./rules --output-valid-dir validated/
  
  SPLIT MODE (--split-rules):
    Parses individual rules from files and validates each separately.
    Useful for isolating issues in multi-rule files.
    
    Example: python %(prog)s ./rules --split-rules --output-valid-dir validated/

EXAMPLES:

  # Validate complete files (recommended)
  python %(prog)s ./rules --output-valid-dir validated/
  
  # Validate files with detailed output
  python %(prog)s ./rules --verbose --output-valid-dir validated/ --output-failed-dir failed/
  
  # Split and validate individual rules
  python %(prog)s ./rules --split-rules --output-valid-dir validated/
  
  # Generate reports
  python %(prog)s ./rules --json-report report.json --markdown-report report.md
        """
    )
    
    parser.add_argument('directory', 
                       help='Directory containing YARA rule files')
    
    parser.add_argument('--split-rules', action='store_true',
                       help='Parse and validate individual rules separately (split mode)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    parser.add_argument('--output-valid-dir', metavar='DIR',
                       help='Output directory for valid files/rules')
    
    parser.add_argument('--output-failed-dir', metavar='DIR',
                       help='Output directory for failed files/rules')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--markdown-report', metavar='FILE',
                       help='Generate Markdown report')
    
    args = parser.parse_args()
    
    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"❌ Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Choose validation mode
        if args.split_rules:
            valid_count, broken_count = validate_split_mode(
                args.directory,
                verbose=args.verbose,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        else:
            valid_count, broken_count = validate_files_mode(
                args.directory,
                verbose=args.verbose,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        
        # Exit codes
        # 0 = success (all valid)
        # 1 = validation failures
        # 2 = no files/rules found
        if valid_count == 0:
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
