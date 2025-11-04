#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CI/CD-Enhanced YARA Rule Validator

This script validates YARA rules and outputs them in formats suitable for CI/CD pipelines.
It separates valid rules from broken ones and provides structured reports.

Usage:
    python validate_yara_rules.py <directory_path> [options]

Examples:
    python validate_yara_rules.py ./rules --output-valid validated/ --output-failed failed/
    python validate_yara_rules.py ./rules --output-valid validated/ --json-report report.json
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
    
    def __init__(self, source, namespace='', include_name='', path=''):
        self.source = source
        self.namespace = namespace
        self.include_name = include_name
        self.path = path
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_source = None
    
    def to_dict(self):
        """Convert rule to dictionary for JSON serialization."""
        return {
            'path': self.path,
            'include_name': self.include_name,
            'namespace': self.namespace,
            'status': self.status,
            'error': self.error_data,
            'has_repair': self.repaired_source is not None
        }
    
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


def write_rules_to_directory(rules, output_dir, use_repaired=False):
    """Write rules to an output directory, preserving directory structure."""
    os.makedirs(output_dir, exist_ok=True)
    
    written_files = []
    for rule in rules:
        if not rule.path:
            continue
        
        # Determine output filename
        output_filename = os.path.basename(rule.path)
        output_path = os.path.join(output_dir, output_filename)
        
        # Write the rule source
        source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(source_to_write)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_combined_rules(rules, output_file, use_repaired=False):
    """Write all rules to a single combined file."""
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"// Combined YARA Rules\n")
        f.write(f"// Generated: {datetime.now().isoformat()}\n")
        f.write(f"// Total rules: {len(rules)}\n\n")
        
        for rule in rules:
            source_to_write = rule.repaired_source if (use_repaired and rule.repaired_source) else rule.source
            
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
            'success_rate': round(len(valid) / (len(valid) + len(broken) + len(repaired)) * 100, 2) if (len(valid) + len(broken) + len(repaired)) > 0 else 0
        },
        'valid_rules': [rule.to_dict() for rule in valid],
        'broken_rules': [rule.to_dict() for rule in broken],
        'repaired_rules': [rule.to_dict() for rule in repaired]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)


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
                f.write(f"- `{rule.path if rule.path else rule.include_name}`\n")
            f.write("\n")
        
        # Repaired rules
        if repaired:
            f.write("## 🔧 Repaired Rules\n\n")
            for rule in repaired:
                f.write(f"- `{rule.path if rule.path else rule.include_name}`\n")
                f.write(f"  - **Repair:** {rule.error_data}\n")
            f.write("\n")
        
        # Broken rules
        if broken:
            f.write("## ❌ Broken Rules\n\n")
            for rule in broken:
                f.write(f"### `{rule.path if rule.path else rule.include_name}`\n\n")
                f.write(f"**Error:**\n```\n{rule.error_data}\n```\n\n")


def validate_directory_cicd(directory, accept_repairs=False, verbose=False,
                            output_valid_dir=None, output_valid_combined=None,
                            output_failed_dir=None, json_report=None,
                            markdown_report=None, namespace=None):
    """Validate YARA rules with CI/CD-friendly outputs."""
    
    print("="*80)
    print("YARA Rule Validation for CI/CD")
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
    
    print(f"\n📁 Found {len(yara_files)} YARA rule file(s)")
    
    # Initialize validator
    validator = YaraValidator(auto_clear=False)
    
    # Add all rule files
    print("\n📥 Loading rules...")
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
                print(f"  ✓ {rule.path if rule.path else rule.include_name}")
        
        if repaired:
            print(f"\n{'='*25} REPAIRED RULES ({len(repaired)}) {'='*25}")
            for rule in repaired:
                print(f"  🔧 {rule.path if rule.path else rule.include_name}")
                print(f"     Repair: {rule.error_data}")
        
        if broken:
            print(f"\n{'='*25} BROKEN RULES ({len(broken)}) {'='*25}")
            for rule in broken:
                print(f"  ❌ {rule.path if rule.path else rule.include_name}")
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
            written = write_rules_to_directory(repaired, output_valid_dir, use_repaired=True)
            print(f"   Wrote {len(written)} repaired file(s)")
    
    if output_valid_combined:
        print(f"\n📝 Writing combined valid rules to: {output_valid_combined}")
        all_valid = valid + repaired
        write_combined_rules(all_valid, output_valid_combined, use_repaired=True)
        print(f"   Wrote {len(all_valid)} rule(s)")
    
    if output_failed_dir and broken:
        print(f"\n📝 Writing failed rules to directory: {output_failed_dir}")
        written = write_rules_to_directory(broken, output_failed_dir, use_repaired=False)
        print(f"   Wrote {len(written)} file(s)")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        generate_json_report(valid, broken, repaired, json_report)
    
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
        description='Validate YARA rules for CI/CD pipelines',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./rules --output-valid-dir validated/
  %(prog)s ./rules --output-valid-combined validated_rules.yar
  %(prog)s ./rules --output-valid-dir validated/ --output-failed-dir failed/
  %(prog)s ./rules --json-report report.json --markdown-report report.md
        """
    )
    
    parser.add_argument('directory', help='Directory containing YARA rule files')
    parser.add_argument('--accept-repairs', action='store_true', 
                       help='Attempt to repair broken rules')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Show detailed output')
    parser.add_argument('--output-valid-dir', metavar='DIR',
                       help='Output directory for valid rules (preserves filenames)')
    parser.add_argument('--output-valid-combined', metavar='FILE',
                       help='Output file for combined valid rules')
    parser.add_argument('--output-failed-dir', metavar='DIR',
                       help='Output directory for failed rules')
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
