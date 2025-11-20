#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Syntax Validator

Validates YARA rules by attempting to compile them with the YARA engine.
This checks for syntax errors, malformed rules, and compilation issues.

Usage:
    python validate_syntax.py <input_dir> --output-valid <valid_dir> --output-failed <failed_dir>
"""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.shared_utils import (
    collect_yara_files,
    write_file_with_header
)

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed. Install it with: pip install yara-python", file=sys.stderr)
    sys.exit(1)


class SyntaxValidator:
    """Validates YARA rule syntax."""
    
    def __init__(self):
        self.valid_files = []
        self.failed_files = []
        self.stats = {
            'total_files': 0,
            'valid_files': 0,
            'failed_files': 0,
            'total_rules': 0
        }
    
    def count_rules(self, content):
        """Count the number of rules in file content."""
        import re
        rule_pattern = re.compile(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+\w+', re.MULTILINE)
        return len(rule_pattern.findall(content))
    
    def validate_file(self, filepath, verbose=False):
        """
        Validate a single YARA file.
        Returns: (is_valid, error_message)
        """
        try:
            # Read file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Count rules
            rule_count = self.count_rules(content)
            
            if rule_count == 0:
                return False, "No rules found in file", content, 0
            
            # Try to compile
            yara.compile(source=content)
            
            if verbose:
                print(f"  ✅ Valid: {os.path.basename(filepath)} ({rule_count} rule(s))")
            
            return True, None, content, rule_count
            
        except yara.Error as e:
            error_msg = str(e)
            if verbose:
                print(f"  ❌ Failed: {os.path.basename(filepath)}")
                print(f"     Error: {error_msg}")
            return False, error_msg, content, rule_count
        
        except Exception as e:
            error_msg = f"Failed to process file: {str(e)}"
            if verbose:
                print(f"  ❌ Error: {os.path.basename(filepath)}")
                print(f"     {error_msg}")
            return False, error_msg, None, 0
    
    def process_directory(self, input_dir, output_valid_dir, output_failed_dir, verbose=False):
        """Process all files in directory."""
        print("="*80)
        print("YARA Syntax Validator")
        print("="*80)
        print(f"Input Directory: {os.path.abspath(input_dir)}")
        try:
            print(f"YARA Version: {yara.__version__}")
        except:
            print("YARA Version: Unknown")
        print("="*80)
        
        # Collect files
        yara_files = collect_yara_files(input_dir)
        
        if not yara_files:
            print(f"\n❌ No YARA files found in {input_dir}")
            return False
        
        print(f"\n📁 Found {len(yara_files)} YARA file(s)")
        self.stats['total_files'] = len(yara_files)
        
        print("\n🔍 Validating syntax...")
        
        # Process each file
        for filepath in yara_files:
            is_valid, error_msg, content, rule_count = self.validate_file(filepath, verbose)
            
            filename = os.path.basename(filepath)
            
            if is_valid:
                # Valid file
                self.stats['valid_files'] += 1
                self.stats['total_rules'] += rule_count
                
                self.valid_files.append({
                    'filepath': filepath,
                    'filename': filename,
                    'rule_count': rule_count
                })
                
                # Write to output directory
                if output_valid_dir and content:
                    output_path = os.path.join(output_valid_dir, filename)
                    
                    header_info = {
                        'Validated': datetime.now().isoformat(),
                        'Source': filepath,
                        'Rules': rule_count,
                        'Status': 'SYNTAX VALID'
                    }
                    
                    write_file_with_header(output_path, content, header_info)
            
            else:
                # Failed file
                self.stats['failed_files'] += 1
                
                self.failed_files.append({
                    'filepath': filepath,
                    'filename': filename,
                    'error': error_msg,
                    'rule_count': rule_count
                })
                
                # Write to failed directory
                if output_failed_dir and content:
                    output_path = os.path.join(output_failed_dir, filename)
                    
                    header_info = {
                        'Validated': datetime.now().isoformat(),
                        'Source': filepath,
                        'Status': 'SYNTAX FAILED',
                        'Error': error_msg
                    }
                    
                    write_file_with_header(output_path, content, header_info)
        
        return True
    
    def get_report(self):
        """Generate report data."""
        return {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'valid_files': self.valid_files,
            'failed_files': self.failed_files
        }


def main():
    parser = argparse.ArgumentParser(
        description='Validate YARA rule syntax',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  
  # Basic validation
  python %(prog)s ./rules --output-valid ./valid --output-failed ./failed
  
  # With JSON report
  python %(prog)s ./rules --output-valid ./valid --json-report syntax_report.json
  
  # Verbose mode
  python %(prog)s ./rules --output-valid ./valid --verbose
        """
    )
    
    parser.add_argument('input_dir',
                       help='Directory containing YARA rules to validate')
    
    parser.add_argument('--output-valid', metavar='DIR',
                       help='Output directory for valid rules')
    
    parser.add_argument('--output-failed', metavar='DIR',
                       help='Output directory for failed rules')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not os.path.isdir(args.input_dir):
        print(f"❌ Error: Input directory not found: {args.input_dir}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Create validator
        validator = SyntaxValidator()
        
        # Process directory
        success = validator.process_directory(
            args.input_dir,
            args.output_valid,
            args.output_failed,
            args.verbose
        )
        
        if not success:
            sys.exit(2)
        
        # Print results
        stats = validator.stats
        print("\n" + "="*80)
        print("SYNTAX VALIDATION RESULTS")
        print("="*80)
        print(f"Total Files:      {stats['total_files']}")
        print(f"✅ Valid Files:   {stats['valid_files']}")
        print(f"❌ Failed Files:  {stats['failed_files']}")
        print(f"📊 Total Rules:   {stats['total_rules']}")
        print("="*80)
        
        # Generate JSON report
        if args.json_report:
            report = validator.get_report()
            os.makedirs(os.path.dirname(args.json_report), exist_ok=True)
            with open(args.json_report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📝 Report saved: {args.json_report}")
        
        # Exit code
        if stats['failed_files'] > 0:
            print(f"\n⚠️  Validation completed with {stats['failed_files']} failure(s)")
            sys.exit(1)
        else:
            print(f"\n✅ All {stats['valid_files']} file(s) validated successfully!")
            sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
