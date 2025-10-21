#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Self-Contained YARA Rule Validator

This script validates all YARA rules in a specified directory.
It performs syntax checking, repair attempts, and detailed reporting.

Usage:
    python validate_yara_rules.py <directory_path> [options]

Examples:
    python validate_yara_rules.py /path/to/yara/rules
    python validate_yara_rules.py ./rules --verbose
    python validate_yara_rules.py ./rules --output report.txt
"""

import argparse
import os
import sys
import glob
import tempfile
import shutil
import re
from pathlib import Path

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
    
    def __init__(self, source, namespace='', include_name='', path=''):
        self.source = source
        self.namespace = namespace
        self.include_name = include_name
        self.path = path
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_source = None
    
    def __str__(self):
        return self.source
    
    def __repr__(self):
        return f"<YaraRule {self.include_name} - {self.status}>"


class YaraValidator:
    """Validates YARA rules with repair capabilities."""
    
    def __init__(self, auto_clear=True):
        self.rules = []
        self.auto_clear = auto_clear
        self.tmp_dir = tempfile.mkdtemp(prefix='yara_validator_')
        self.include_map = {}
    
    def add_rule_source(self, source, namespace='', include_name=''):
        """Add a YARA rule from source string."""
        rule = YaraRule(source, namespace, include_name)
        self.rules.append(rule)
        if include_name:
            self.include_map[include_name] = rule
    
    def add_rule_file(self, filepath, namespace='', include_name=''):
        """Add a YARA rule from file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source = f.read()
            
            if not include_name:
                include_name = os.path.basename(filepath)
            if not namespace:
                namespace = os.path.dirname(filepath)
            
            rule = YaraRule(source, namespace, include_name, filepath)
            self.rules.append(rule)
            self.include_map[include_name] = rule
        except Exception as e:
            print(f"Error reading file {filepath}: {e}", file=sys.stderr)
    
    def _attempt_repair(self, source):
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
        """Validate a single rule."""
        try:
            # Try to compile the rule
            yara.compile(source=rule.source)
            rule.status = YaraRule.STATUS_VALID
            return True
        except yara.Error as e:
            rule.error_data = str(e)
            
            # Try to repair
            if accept_repairs:
                repaired_source, repairs = self._attempt_repair(rule.source)
                if repaired_source != rule.source:
                    try:
                        yara.compile(source=repaired_source)
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


def print_separator(char='=', length=80):
    """Print a separator line."""
    print(char * length)


def print_rule_details(rule, show_source=True):
    """Print details about a rule."""
    print(f"\nNamespace: {rule.namespace}")
    if rule.include_name:
        print(f"Include Name: {rule.include_name}")
    if rule.path:
        print(f"File Path: {rule.path}")
    print(f"Status: {rule.status}")
    
    if rule.status == YaraRule.STATUS_BROKEN or rule.status == YaraRule.STATUS_REPAIRED:
        print(f"Details: {rule.error_data}")
    
    if show_source:
        print("\nSource:")
        lines = rule.source.split('\n')
        for i, line in enumerate(lines[:20], 1):
            print(f"  {i:3d}: {line}")
        if len(lines) > 20:
            print(f"  ... ({len(lines) - 20} more lines)")


def validate_directory(directory, accept_repairs=False, verbose=False, 
                       output_file=None, namespace=None):
    """Validate all YARA rules in a directory."""
    original_stdout = sys.stdout
    if output_file:
        sys.stdout = open(output_file, 'w', encoding='utf-8')
    
    try:
        print("YARA Rule Validation Report")
        print(f"Directory: {os.path.abspath(directory)}")
        try:
            print(f"YARA Version: {yara.__version__}")
        except:
            print("YARA Version: Unknown")
        print_separator()
        
        # Collect YARA files
        yara_files = collect_yara_files(directory)
        
        if not yara_files:
            print(f"\nNo YARA rule files found in {directory}")
            return 0, 0, 0
        
        print(f"\nFound {len(yara_files)} YARA rule file(s)")
        
        # Initialize validator
        validator = YaraValidator(auto_clear=False)
        
        # Add all rule files
        print("\nLoading rules...")
        for yara_file in yara_files:
            try:
                include_name = os.path.basename(yara_file)
                rule_namespace = namespace if namespace else os.path.dirname(yara_file)
                validator.add_rule_file(yara_file, namespace=rule_namespace, include_name=include_name)
                if verbose:
                    print(f"  ✓ Loaded: {yara_file}")
            except Exception as e:
                print(f"  ✗ Error loading {yara_file}: {e}")
        
        # Validate all rules
        print("\nValidating rules...")
        valid, broken, repaired = validator.check_all(accept_repairs=accept_repairs)
        
        # Print results
        print_separator()
        print(f"\n{'='*25} VALIDATION SUMMARY {'='*25}")
        print(f"Total files processed: {len(yara_files)}")
        print(f"Valid rules: {len(valid)}")
        print(f"Broken rules: {len(broken)}")
        print(f"Repaired rules: {len(repaired)}")
        print_separator()
        
        # Print valid rules
        if valid:
            print(f"\n{'='*25} VALID RULES ({len(valid)}) {'='*25}")
            for rule in valid:
                if verbose:
                    print_rule_details(rule, show_source=True)
                else:
                    path = rule.path if rule.path else "inline"
                    print(f"✓ {path}")
        
        # Print broken rules
        if broken:
            print(f"\n{'='*25} BROKEN RULES ({len(broken)}) {'='*25}")
            for rule in broken:
                print_rule_details(rule, show_source=verbose)
        
        # Print repaired rules
        if repaired:
            print(f"\n{'='*25} REPAIRED RULES ({len(repaired)}) {'='*25}")
            for rule in repaired:
                print_rule_details(rule, show_source=True)
        
        # Cleanup
        validator.clear_tmp()
        
        print_separator()
        print("\nValidation complete!")
        
        return len(valid), len(broken), len(repaired)
    
    finally:
        if output_file:
            sys.stdout.close()
            sys.stdout = original_stdout
            print(f"Report written to: {output_file}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Validate YARA rules in a directory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/rules
  %(prog)s ./rules --verbose
  %(prog)s ./rules --accept-repairs --output report.txt
  %(prog)s ./rules --namespace my_rules
        """
    )
    
    parser.add_argument('directory', help='Directory containing YARA rule files')
    parser.add_argument('--accept-repairs', action='store_true', help='Attempt to repair broken rules')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')
    parser.add_argument('--output', '-o', metavar='FILE', help='Write report to file')
    parser.add_argument('--namespace', '-n', metavar='NAME', help='Namespace for all rules')
    parser.add_argument('--extensions', '-e', nargs='+', metavar='EXT',
                       default=['.yar', '.yara', '.rule'], help='File extensions to search')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    try:
        valid_count, broken_count, repaired_count = validate_directory(
            args.directory,
            accept_repairs=args.accept_repairs,
            verbose=args.verbose,
            output_file=args.output,
            namespace=args.namespace
        )
        
        sys.exit(1 if broken_count > 0 else 0)
            
    except Exception as e:
        print(f"Error during validation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
