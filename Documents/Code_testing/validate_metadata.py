#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Metadata Validator

Validates YARA rule metadata against required standards and formats.
Checks for required fields, date formats, and restricted values.

Usage:
    python validate_metadata.py <input_dir> --json-report metadata_report.json
    python validate_metadata.py <input_dir> --move-invalid <failed_dir>
"""

import argparse
import os
import sys
import json
import re
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.shared_utils import (
    collect_yara_files,
    parse_yara_file_to_rules,
    extract_rule_name,
    write_file_with_header
)


# ============================================================================
# METADATA VALIDATION CONFIGURATION
# ============================================================================

# Required metadata fields
REQUIRED_METADATA_FIELDS = [
    'author',
    'date',
    'last_modified',
    'category',
    'description',
    'classification',
    'scope',
    'platform'
]

# Fields with restricted values
METADATA_VALUE_RESTRICTIONS = {
    'classification': ['Hunting', 'Production', 'Experimental'],
    'scope': ['file', 'memory', 'process', 'network'],
    'platform': ['windows', 'linux', 'macos', 'generic']
}

# Date format patterns
DATE_PATTERNS = {
    'date': r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
    'last_modified': r'^\d{8}_\d{4}$'  # YYYYMMDD_HHMM
}


# ============================================================================
# METADATA VALIDATION
# ============================================================================

class MetadataValidationError:
    """Represents a metadata validation error."""
    
    TYPE_MISSING_FIELD = 'missing_field'
    TYPE_INVALID_FORMAT = 'invalid_format'
    TYPE_INVALID_VALUE = 'invalid_value'
    TYPE_EMPTY_VALUE = 'empty_value'
    
    def __init__(self, error_type, field_name, message, expected_value=None, actual_value=None):
        self.error_type = error_type
        self.field_name = field_name
        self.message = message
        self.expected_value = expected_value
        self.actual_value = actual_value
    
    def to_dict(self):
        result = {
            'type': self.error_type,
            'field': self.field_name,
            'message': self.message
        }
        if self.expected_value:
            result['expected'] = self.expected_value
        if self.actual_value is not None:
            result['actual'] = self.actual_value
        return result
    
    def __str__(self):
        return f"{self.field_name}: {self.message}"


class MetadataValidator:
    """Validates YARA rule metadata against required template."""
    
    def __init__(self):
        self.passed_rules = []
        self.failed_rules = []
        self.stats = {
            'total_files': 0,
            'total_rules': 0,
            'passed': 0,
            'failed': 0
        }
    
    def extract_metadata(self, rule_source):
        """
        Extract metadata section from YARA rule source.
        Returns: dict of {field_name: value}
        """
        metadata = {}
        
        # Find the meta: section
        meta_match = re.search(r'meta:\s*(.*?)(?:strings:|condition:|\})', 
                              rule_source, re.DOTALL | re.IGNORECASE)
        
        if not meta_match:
            return metadata
        
        meta_content = meta_match.group(1)
        
        # Parse metadata fields (handle both quoted and unquoted values)
        field_pattern = r'(\w+)\s*=\s*(?:"([^"]*)"|(\S+))'
        
        for match in re.finditer(field_pattern, meta_content):
            field_name = match.group(1)
            # Use quoted value if present, otherwise use unquoted value
            field_value = match.group(2) if match.group(2) is not None else match.group(3)
            metadata[field_name] = field_value
        
        return metadata
    
    def validate_rule_metadata(self, rule_source, rule_name='unknown'):
        """
        Validate metadata in a YARA rule.
        Returns: (is_valid, list_of_errors)
        """
        errors = []
        metadata = self.extract_metadata(rule_source)
        
        # Check for required fields
        for field in REQUIRED_METADATA_FIELDS:
            if field not in metadata:
                errors.append(MetadataValidationError(
                    MetadataValidationError.TYPE_MISSING_FIELD,
                    field,
                    f"Required metadata field '{field}' is missing"
                ))
            else:
                value = metadata[field].strip()
                
                # Check if value is empty
                if not value:
                    errors.append(MetadataValidationError(
                        MetadataValidationError.TYPE_EMPTY_VALUE,
                        field,
                        f"Metadata field '{field}' is empty",
                        actual_value=value
                    ))
                    continue
                
                # Validate date formats
                if field in DATE_PATTERNS:
                    pattern = DATE_PATTERNS[field]
                    if not re.match(pattern, value):
                        expected_format = "YYYY-MM-DD" if field == 'date' else "YYYYMMDD_HHMM"
                        errors.append(MetadataValidationError(
                            MetadataValidationError.TYPE_INVALID_FORMAT,
                            field,
                            f"Date format invalid for '{field}' (expected: {expected_format})",
                            expected_value=expected_format,
                            actual_value=value
                        ))
                
                # Validate restricted values
                if field in METADATA_VALUE_RESTRICTIONS:
                    allowed_values = METADATA_VALUE_RESTRICTIONS[field]
                    if value not in allowed_values:
                        errors.append(MetadataValidationError(
                            MetadataValidationError.TYPE_INVALID_VALUE,
                            field,
                            f"Invalid value for '{field}' (must be one of: {', '.join(allowed_values)})",
                            expected_value=allowed_values,
                            actual_value=value
                        ))
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def validate_file(self, filepath, verbose=False):
        """
        Validate metadata for all rules in a file.
        Returns: (all_valid, file_errors)
        """
        if verbose:
            print(f"\n📄 Validating: {os.path.basename(filepath)}")
        
        imports, rule_sources = parse_yara_file_to_rules(filepath)
        
        all_valid = True
        file_errors = []
        
        for rule_source in rule_sources:
            self.stats['total_rules'] += 1
            
            rule_name = extract_rule_name(rule_source)
            if not rule_name:
                continue
            
            is_valid, errors = self.validate_rule_metadata(rule_source, rule_name)
            
            if is_valid:
                self.stats['passed'] += 1
                self.passed_rules.append({
                    'rule_name': rule_name,
                    'file': filepath
                })
                
                if verbose:
                    print(f"  ✅ Valid: {rule_name}")
            else:
                all_valid = False
                self.stats['failed'] += 1
                
                error_info = {
                    'rule_name': rule_name,
                    'file': filepath,
                    'errors': [e.to_dict() for e in errors]
                }
                
                self.failed_rules.append(error_info)
                file_errors.append(error_info)
                
                if verbose:
                    print(f"  ❌ Failed: {rule_name}")
                    for error in errors:
                        print(f"     • {error}")
        
        return all_valid, file_errors
    
    def process_directory(self, input_dir, move_invalid_dir, verbose=False):
        """Process all files in directory."""
        print("="*80)
        print("YARA Metadata Validator")
        print("="*80)
        print(f"Input Directory: {os.path.abspath(input_dir)}")
        print(f"Required Fields: {', '.join(REQUIRED_METADATA_FIELDS)}")
        print("="*80)
        
        # Collect files
        yara_files = collect_yara_files(input_dir)
        
        if not yara_files:
            print(f"\n❌ No YARA files found in {input_dir}")
            return False
        
        print(f"\n📁 Found {len(yara_files)} YARA file(s)")
        self.stats['total_files'] = len(yara_files)
        
        print("\n🔍 Validating metadata...")
        
        # Process each file
        for filepath in yara_files:
            all_valid, file_errors = self.validate_file(filepath, verbose)
            
            # If metadata validation failed and move directory specified
            if not all_valid and move_invalid_dir:
                filename = os.path.basename(filepath)
                output_path = os.path.join(move_invalid_dir, filename)
                
                # Read original content
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Create header with error details
                header_info = {
                    'Source': filepath,
                    'Validated': datetime.now().isoformat(),
                    'Status': 'METADATA VALIDATION FAILED',
                    'Errors': f"{len(file_errors)} rule(s) with metadata issues"
                }
                
                write_file_with_header(output_path, content, header_info)
                
                if verbose:
                    print(f"  📝 Moved to failed directory: {filename}")
        
        return True
    
    def get_report(self):
        """Generate report data."""
        return {
            'timestamp': datetime.now().isoformat(),
            'required_fields': REQUIRED_METADATA_FIELDS,
            'value_restrictions': METADATA_VALUE_RESTRICTIONS,
            'date_formats': {
                'date': 'YYYY-MM-DD',
                'last_modified': 'YYYYMMDD_HHMM'
            },
            'statistics': self.stats,
            'passed_rules': self.passed_rules,
            'failed_rules': self.failed_rules
        }
    
    def get_metadata_template(self):
        """Return a string showing the required metadata template."""
        template = """meta:
    author = ""
    date = "YYYY-MM-DD"
    last_modified = "YYYYMMDD_HHMM"
    category = ""
    description = ""
    classification = "Hunting | Production | Experimental"
    scope = "file | memory | process | network"
    platform = "windows | linux | macos | generic"
"""
        return template


def main():
    parser = argparse.ArgumentParser(
        description='Validate YARA rule metadata',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
REQUIRED METADATA FIELDS:
  - author: Rule author name
  - date: Creation date (YYYY-MM-DD)
  - last_modified: Last modification timestamp (YYYYMMDD_HHMM)
  - category: Rule category/purpose
  - description: Detailed rule description
  - classification: Hunting | Production | Experimental
  - scope: file | memory | process | network
  - platform: windows | linux | macos | generic

EXAMPLES:
  
  # Validate metadata in rules
  python %(prog)s ./rules --json-report metadata_report.json
  
  # Move invalid rules to separate directory
  python %(prog)s ./rules --move-invalid ./metadata_errors
  
  # Show metadata template
  python %(prog)s --show-template
  
  # Verbose mode
  python %(prog)s ./rules --json-report metadata_report.json --verbose
        """
    )
    
    parser.add_argument('input_dir', nargs='?',
                       help='Directory containing YARA rules to validate')
    
    parser.add_argument('--move-invalid', metavar='DIR',
                       help='Move files with invalid metadata to this directory')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--show-template', action='store_true',
                       help='Show required metadata template and exit')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    args = parser.parse_args()
    
    # Show template if requested
    if args.show_template:
        validator = MetadataValidator()
        print("="*80)
        print("REQUIRED METADATA TEMPLATE")
        print("="*80)
        print(validator.get_metadata_template())
        print("="*80)
        print("\nREQUIRED FIELDS:")
        for field in REQUIRED_METADATA_FIELDS:
            print(f"  • {field}")
        print("\nRESTRICTED VALUES:")
        for field, values in METADATA_VALUE_RESTRICTIONS.items():
            print(f"  • {field}: {', '.join(values)}")
        print("\nDATE FORMATS:")
        print("  • date: YYYY-MM-DD (e.g., 2024-03-15)")
        print("  • last_modified: YYYYMMDD_HHMM (e.g., 20240315_1430)")
        print("="*80)
        sys.exit(0)
    
    # Validate input directory
    if not args.input_dir:
        parser.error("input_dir is required (use --show-template to see metadata requirements)")
    
    if not os.path.isdir(args.input_dir):
        print(f"❌ Error: Input directory not found: {args.input_dir}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Create validator
        validator = MetadataValidator()
        
        # Process directory
        success = validator.process_directory(
            args.input_dir,
            args.move_invalid,
            args.verbose
        )
        
        if not success:
            sys.exit(2)
        
        # Print results
        stats = validator.stats
        print("\n" + "="*80)
        print("METADATA VALIDATION RESULTS")
        print("="*80)
        print(f"Total Files:      {stats['total_files']}")
        print(f"Total Rules:      {stats['total_rules']}")
        print(f"✅ Valid:         {stats['passed']}")
        print(f"❌ Failed:        {stats['failed']}")
        print("="*80)
        
        # Generate JSON report
        if args.json_report:
            report = validator.get_report()
            report_dir = os.path.dirname(args.json_report)
            if report_dir:
                os.makedirs(report_dir, exist_ok=True)
            with open(args.json_report, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            print(f"\n📝 Report saved: {args.json_report}")
        
        # Exit code
        if stats['failed'] > 0:
            print(f"\n⚠️  Validation completed with {stats['failed']} failure(s)")
            sys.exit(1)
        else:
            print(f"\n✅ All metadata validated successfully!")
            sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
