#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CI/CD-Enhanced YARA Rule Validator with Dependency-Aware Multi-Rule Support

This script validates YARA rules and handles complex multi-rule files with:
- Import statement preservation
- Inter-rule dependency detection and grouping
- Independent validation while maintaining rule relationships

Usage:
    python validate_yara_rules.py <directory_path> [options]

Examples:
    python validate_yara_rules.py ./rules --output-valid-dir validated/ --output-failed-dir failed/
    python validate_yara_rules.py ./rules --keep-dependencies --verbose
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
from collections import defaultdict

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed. Install it with: pip install yara-python", file=sys.stderr)
    sys.exit(1)


class YaraRule:
    """Represents a single YARA rule with validation status and dependencies."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    STATUS_REPAIRED = 'repaired'
    
    def __init__(self, source, namespace='', include_name='', path='', rule_name='', 
                 imports='', dependencies=None):
        self.source = source
        self.namespace = namespace
        self.include_name = include_name
        self.path = path
        self.rule_name = rule_name
        self.imports = imports
        self.dependencies = dependencies or []  # List of rule names this rule depends on
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_source = None
        self.dependency_group = None  # Group ID for dependent rules
    
    def get_full_source(self, include_dependencies=None):
        """
        Get complete source including imports and optionally dependent rules.
        
        Args:
            include_dependencies: List of YaraRule objects to include
        """
        parts = []
        
        # Add imports
        if self.imports:
            parts.append(self.imports)
        
        # Add dependent rules first
        if include_dependencies:
            for dep_rule in include_dependencies:
                parts.append(f"// Dependency: {dep_rule.rule_name}")
                parts.append(dep_rule.source)
        
        # Add main rule
        parts.append(self.source)
        
        return '\n\n'.join(parts)
    
    def to_dict(self):
        """Convert rule to dictionary for JSON serialization."""
        return {
            'path': self.path,
            'include_name': self.include_name,
            'rule_name': self.rule_name,
            'namespace': self.namespace,
            'status': self.status,
            'error': self.error_data,
            'has_repair': self.repaired_source is not None,
            'dependencies': self.dependencies,
            'dependency_group': self.dependency_group
        }
    
    def __str__(self):
        return self.source
    
    def __repr__(self):
        return f"<YaraRule {self.rule_name} - {self.status}>"


def extract_rule_name(rule_source):
    """Extract the rule name from rule source code."""
    match = re.search(r'^\s*(?:private\s+|global\s+)?rule\s+(\w+)', rule_source, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown_rule"


def extract_rule_dependencies(rule_source, available_rules):
    """
    Extract rule dependencies from a rule's condition section.
    
    Args:
        rule_source: The rule source code
        available_rules: Set of available rule names in the same file
    
    Returns:
        List of rule names this rule depends on
    """
    dependencies = []
    
    # Extract the condition section
    condition_match = re.search(r'condition:\s*(.+?)(?=\}[\s]*$)', rule_source, re.DOTALL)
    if not condition_match:
        return dependencies
    
    condition = condition_match.group(1)
    
    # Look for rule references in the condition
    # Patterns: rulename, not rulename, rulename at offset, rulename in range
    for rule_name in available_rules:
        # Match rule name as a whole word (not part of another identifier)
        pattern = r'\b' + re.escape(rule_name) + r'\b'
        if re.search(pattern, condition):
            dependencies.append(rule_name)
    
    return dependencies


def parse_yara_file(filepath):
    """
    Parse a YARA file and extract individual rules with their imports and dependencies.
    
    Returns:
        tuple: (imports_string, list_of_rule_dicts)
        where each rule_dict contains: {'source': str, 'name': str, 'dependencies': list}
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
    rules = []
    rule_pattern = r'(^\s*(?:private\s+|global\s+)?rule\s+\w+.*?^\})'
    matches = re.finditer(rule_pattern, content, re.MULTILINE | re.DOTALL)
    
    for match in matches:
        rule_source = match.group(1)
        rule_source = rule_source.strip()
        
        # Verify it's a complete rule by counting braces
        if rule_source.count('{') == rule_source.count('}'):
            rules.append(rule_source)
        else:
            # Try to fix brace mismatch
            open_braces = rule_source.count('{')
            close_braces = rule_source.count('}')
            if open_braces > close_braces:
                rule_source += '\n' + '}' * (open_braces - close_braces)
                rules.append(rule_source)
    
    # If no rules found with the pattern, treat entire file as one rule
    if not rules:
        content_without_imports = content
        for import_line in import_lines:
            content_without_imports = content_without_imports.replace(import_line, '', 1)
        content_without_imports = content_without_imports.strip()
        
        if content_without_imports:
            rules.append(content_without_imports)
    
    # Extract rule names and dependencies
    rule_names = set([extract_rule_name(r) for r in rules])
    rule_data = []
    
    for rule_source in rules:
        rule_name = extract_rule_name(rule_source)
        # Find dependencies (references to other rules in the same file)
        other_rules = rule_names - {rule_name}
        dependencies = extract_rule_dependencies(rule_source, other_rules)
        
        rule_data.append({
            'source': rule_source,
            'name': rule_name,
            'dependencies': dependencies
        })
    
    return imports_string, rule_data


def build_dependency_groups(rules_data):
    """
    Build groups of rules that must be validated together due to dependencies.
    
    Args:
        rules_data: List of dicts with 'name' and 'dependencies'
    
    Returns:
        Dict mapping group_id to list of rule names in that group
    """
    # Create a graph of dependencies
    rule_to_deps = {r['name']: set(r['dependencies']) for r in rules_data}
    
    # Find connected components (groups of interdependent rules)
    visited = set()
    groups = []
    
    def dfs(rule_name, current_group):
        """Depth-first search to find all connected rules."""
        if rule_name in visited:
            return
        visited.add(rule_name)
        current_group.add(rule_name)
        
        # Follow forward dependencies
        for dep in rule_to_deps.get(rule_name, []):
            dfs(dep, current_group)
        
        # Follow backward dependencies (rules that depend on this one)
        for other_rule, other_deps in rule_to_deps.items():
            if rule_name in other_deps:
                dfs(other_rule, current_group)
    
    # Build groups
    for rule_name in rule_to_deps.keys():
        if rule_name not in visited:
            current_group = set()
            dfs(rule_name, current_group)
            if len(current_group) > 1:
                # Only create a group if there are actual dependencies
                groups.append(list(current_group))
            else:
                # Single rule with no dependencies
                groups.append([rule_name])
    
    # Convert to dict with group IDs
    group_dict = {}
    for group_id, group_members in enumerate(groups):
        group_dict[group_id] = group_members
    
    return group_dict


class YaraValidator:
    """Validates YARA rules with repair capabilities and dependency handling."""
    
    def __init__(self, auto_clear=True, keep_dependencies=True):
        self.rules = []
        self.auto_clear = auto_clear
        self.keep_dependencies = keep_dependencies
        self.tmp_dir = tempfile.mkdtemp(prefix='yara_validator_')
        self.include_map = {}
        self.rule_map = {}  # Map rule names to YaraRule objects
    
    def add_rule_source(self, source, namespace='', include_name='', rule_name='', 
                       imports='', dependencies=None):
        """Add a YARA rule from source string."""
        if not rule_name:
            rule_name = extract_rule_name(source)
        
        rule = YaraRule(source, namespace, include_name, '', rule_name, imports, dependencies)
        self.rules.append(rule)
        self.rule_map[rule_name] = rule
        if include_name:
            self.include_map[include_name] = rule
    
    def add_rule_file(self, filepath, namespace='', include_name=''):
        """Add YARA rules from file, parsing multiple rules and their dependencies."""
        try:
            if not include_name:
                include_name = os.path.basename(filepath)
            if not namespace:
                namespace = os.path.dirname(filepath)
            
            # Parse file to extract imports and individual rules with dependencies
            imports, rules_data = parse_yara_file(filepath)
            
            if not rules_data:
                print(f"  ⚠️  No rules found in {filepath}", file=sys.stderr)
                return
            
            # Build dependency groups if keeping dependencies
            if self.keep_dependencies and len(rules_data) > 1:
                dep_groups = build_dependency_groups(rules_data)
            else:
                # Each rule is its own group
                dep_groups = {i: [r['name']] for i, r in enumerate(rules_data)}
            
            # Create YaraRule objects
            for rule_data in rules_data:
                rule_name = rule_data['name']
                
                # Find which group this rule belongs to
                group_id = None
                for gid, members in dep_groups.items():
                    if rule_name in members:
                        group_id = gid
                        break
                
                # Create unique include name
                if len(rules_data) > 1:
                    rule_include_name = f"{include_name}::{rule_name}"
                else:
                    rule_include_name = include_name
                
                rule = YaraRule(
                    source=rule_data['source'],
                    namespace=namespace,
                    include_name=rule_include_name,
                    path=filepath,
                    rule_name=rule_name,
                    imports=imports,
                    dependencies=rule_data['dependencies']
                )
                rule.dependency_group = group_id
                
                self.rules.append(rule)
                self.rule_map[rule_name] = rule
                self.include_map[rule_include_name] = rule
                
        except Exception as e:
            print(f"Error processing file {filepath}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
    
    def _get_dependency_rules(self, rule):
        """Get all YaraRule objects that this rule depends on."""
        dep_rules = []
        for dep_name in rule.dependencies:
            if dep_name in self.rule_map:
                dep_rules.append(self.rule_map[dep_name])
        return dep_rules
    
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
        
        # Fix missing braces
        if repaired.count('{') != repaired.count('}'):
            if repaired.count('{') > repaired.count('}'):
                repaired += '\n}'
                repairs.append("Added missing closing brace")
        
        # Fix missing rule name
        if not re.search(r'rule\s+\w+\s*\{', repaired):
            if 'rule' in repaired and '{' in repaired:
                repaired = re.sub(r'rule\s*\{', 'rule DefaultRule {', repaired)
                repairs.append("Added missing rule name")
        
        return repaired, repairs
    
    def _validate_rule(self, rule, accept_repairs=False):
        """Validate a single rule with its dependencies."""
        try:
            # Get dependent rules if keeping dependencies
            dependent_rules = []
            if self.keep_dependencies:
                dependent_rules = self._get_dependency_rules(rule)
            
            # Try to compile the rule with imports and dependencies
            full_source = rule.get_full_source(include_dependencies=dependent_rules)
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
                        # Create a repaired rule and test with dependencies
                        repaired_rule = YaraRule(
                            source=repaired_source,
                            imports=rule.imports,
                            rule_name=rule.rule_name,
                            dependencies=rule.dependencies
                        )
                        full_repaired = repaired_rule.get_full_source(
                            include_dependencies=dependent_rules if self.keep_dependencies else None
                        )
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


def write_rules_to_directory(rules, output_dir, use_repaired=False, rule_map=None, keep_dependencies=True):
    """Write rules to an output directory using rule names as filenames, including dependencies."""
    os.makedirs(output_dir, exist_ok=True)
    
    written_files = []
    rule_name_counts = {}
    
    # Group rules by dependency group if keeping dependencies
    if keep_dependencies and rule_map:
        groups = defaultdict(list)
        standalone_rules = []
        
        for rule in rules:
            if rule.dependency_group is not None and rule.dependencies:
                groups[rule.dependency_group].append(rule)
            else:
                standalone_rules.append(rule)
        
        # Write grouped rules
        for group_id, group_rules in groups.items():
            # Sort by dependencies (dependencies first)
            sorted_group = sorted(group_rules, key=lambda r: len(r.dependencies))
            
            # Use the name of the main rule (one with dependencies) for filename
            main_rule = max(sorted_group, key=lambda r: len(r.dependencies))
            base_filename = f"{main_rule.rule_name}_with_deps"
            
            if base_filename in rule_name_counts:
                rule_name_counts[base_filename] += 1
                output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
            else:
                rule_name_counts[base_filename] = 1
                output_filename = f"{base_filename}.yar"
            
            output_path = os.path.join(output_dir, output_filename)
            
            # Write all rules in the group
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    # Header
                    f.write(f"// Dependency Group: {group_id}\n")
                    f.write(f"// Rules: {', '.join([r.rule_name for r in sorted_group])}\n")
                    if main_rule.path:
                        f.write(f"// Source: {main_rule.path}\n")
                    f.write(f"// Validated: {datetime.now().isoformat()}\n\n")
                    
                    # Imports (once for all rules)
                    if main_rule.imports:
                        f.write(main_rule.imports)
                        f.write("\n\n")
                    
                    # Write each rule
                    for rule in sorted_group:
                        source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
                        f.write(f"// Rule: {rule.rule_name}\n")
                        if rule.dependencies:
                            f.write(f"// Dependencies: {', '.join(rule.dependencies)}\n")
                        f.write(source_to_write)
                        f.write("\n\n")
                
                written_files.append(output_path)
            except Exception as e:
                print(f"Error writing {output_path}: {e}", file=sys.stderr)
        
        # Write standalone rules
        rules = standalone_rules
    
    # Write individual rules (no dependencies)
    for rule in rules:
        base_filename = rule.rule_name if rule.rule_name else "unknown_rule"
        
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
        
        # Include imports in the output
        full_source = f"{rule.imports}\n\n{source_to_write}" if rule.imports else source_to_write
        
        # Add header comment
        header = f"// Rule: {rule.rule_name}\n"
        if rule.path:
            header += f"// Source: {rule.path}\n"
        if rule.dependencies:
            header += f"// Note: This rule has dependencies: {', '.join(rule.dependencies)}\n"
            header += f"// Dependencies should be present for validation\n"
        header += f"// Validated: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_rules_to_directory(rules, output_dir, rule_map=None, keep_dependencies=True):
    """Write failed rules to directory with error information and dependencies."""
    os.makedirs(output_dir, exist_ok=True)
    
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name if rule.rule_name else "unknown_rule"
        
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Get dependent rules if available
        dependent_rules = []
        if keep_dependencies and rule_map and rule.dependencies:
            for dep_name in rule.dependencies:
                if dep_name in rule_map:
                    dependent_rules.append(rule_map[dep_name])
        
        # Build full source with dependencies
        parts = []
        if rule.imports:
            parts.append(rule.imports)
        
        if dependent_rules:
            for dep_rule in dependent_rules:
                parts.append(f"// Dependency: {dep_rule.rule_name}")
                parts.append(dep_rule.source)
        
        parts.append(rule.source)
        full_source = '\n\n'.join(parts)
        
        # Add header with error information
        header = f"// VALIDATION FAILED\n"
        header += f"// Rule: {rule.rule_name}\n"
        if rule.path:
            header += f"// Source: {rule.path}\n"
        header += f"// Error: {rule.error_data}\n"
        if rule.dependencies:
            header += f"// Dependencies: {', '.join(rule.dependencies)}\n"
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
            if rule.dependencies:
                f.write(f"// Dependencies: {', '.join(rule.dependencies)}\n")
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
                f.write(f"- **{rule.rule_name}** (`{source_file}`)")
                if rule.dependencies:
                    f.write(f" - Dependencies: {', '.join(rule.dependencies)}")
                f.write("\n")
            f.write("\n")
        
        # Repaired rules
        if repaired:
            f.write("## 🔧 Repaired Rules\n\n")
            for rule in repaired:
                source_file = rule.path if rule.path else "inline"
                f.write(f"### **{rule.rule_name}** (`{source_file}`)\n\n")
                f.write(f"**Repair Applied:** {rule.error_data}\n\n")
                if rule.dependencies:
                    f.write(f"**Dependencies:** {', '.join(rule.dependencies)}\n\n")
                f.write("<details>\n")
                f.write("<summary>View repaired source</summary>\n\n")
                f.write("```yara\n")
                full_source = f"{rule.imports}\n\n{rule.repaired_source}" if rule.imports and rule.repaired_source else (rule.repaired_source or "")
                lines = full_source.split('\n')
                for line in lines[:30]:
                    f.write(f"{line}\n")
                if len(lines) > 30:
                    f.write(f"... ({len(lines) - 30} more lines)\n")
