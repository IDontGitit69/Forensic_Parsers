#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
YARA Rule Validator Driver Script

This script validates all YARA rules in a specified directory using the yara_validator module.
It provides detailed reporting on valid, broken, and repaired rules.

Usage:
    python validate_yara_rules.py <directory_path> [options]

Examples:
    python validate_yara_rules.py /path/to/yara/rules
    python validate_yara_rules.py ./rules --accept-repairs --output report.txt
"""

import argparse
import os
import sys
import glob
import yara_validator


def collect_yara_files(directory, extensions=None):
    """
    Collect all YARA rule files from a directory.
    
    Args:
        directory: Path to directory containing YARA rules
        extensions: List of file extensions to look for (default: .yar, .yara)
    
    Returns:
        List of absolute paths to YARA rule files
    """
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
    
    if rule.status == yara_validator.YaraSource.STATUS_BROKEN:
        print(f"Error: {rule.error_data}")
    
    if show_source:
        print("\nSource:")
        print(rule)


def validate_directory(directory, accept_repairs=False, verbose=False, 
                       output_file=None, namespace=None):
    """
    Validate all YARA rules in a directory.
    
    Args:
        directory: Path to directory containing YARA rules
        accept_repairs: Whether to accept repaired rules
        verbose: Show detailed output for each rule
        output_file: Optional file to write report to
        namespace: Optional namespace to use for all rules
    
    Returns:
        Tuple of (valid_count, broken_count, repaired_count)
    """
    # Redirect output if needed
    original_stdout = sys.stdout
    if output_file:
        sys.stdout = open(output_file, 'w', encoding='utf-8')
    
    try:
        print(f"YARA Rule Validation Report")
        print(f"Directory: {os.path.abspath(directory)}")
        print(f"YARA Version: {yara_validator.YARA_VERSION}")
        print_separator()
        
        # Collect YARA files
        yara_files = collect_yara_files(directory)
        
        if not yara_files:
            print(f"\nNo YARA rule files found in {directory}")
            return 0, 0, 0
        
        print(f"\nFound {len(yara_files)} YARA rule file(s)")
        
        # Initialize validator
        validator = yara_validator.YaraValidator(auto_clear=False)
        
        # Add all rule files
        print("\nLoading rules...")
        for yara_file in yara_files:
            try:
                # Use filename as include name, or namespace if provided
                include_name = os.path.basename(yara_file)
                rule_namespace = namespace if namespace else os.path.dirname(yara_file)
                
                validator.add_rule_file(
                    yara_file,
                    namespace=rule_namespace,
                    include_name=include_name
                )
                if verbose:
                    print(f"  Loaded: {yara_file}")
            except Exception as e:
                print(f"  Error loading {yara_file}: {e}")
        
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
        print(f"\nValidation complete!")
        
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
    
    parser.add_argument(
        'directory',
        help='Directory containing YARA rule files'
    )
    
    parser.add_argument(
        '--accept-repairs',
        action='store_true',
        help='Accept and use repaired rules during validation'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output for each rule'
    )
    
    parser.add_argument(
        '--output', '-o',
        metavar='FILE',
        help='Write report to specified file'
    )
    
    parser.add_argument(
        '--namespace', '-n',
        metavar='NAME',
        help='Use specified namespace for all rules'
    )
    
    parser.add_argument(
        '--extensions', '-e',
        nargs='+',
        metavar='EXT',
        default=['.yar', '.yara', '.rule'],
        help='File extensions to search for (default: .yar .yara .rule)'
    )
    
    args = parser.parse_args()
    
    # Check if directory exists
    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    # Run validation
    try:
        valid_count, broken_count, repaired_count = validate_directory(
            args.directory,
            accept_repairs=args.accept_repairs,
            verbose=args.verbose,
            output_file=args.output,
            namespace=args.namespace
        )
        
        # Exit with appropriate code
        if broken_count > 0:
            sys.exit(1)  # Error exit if any rules are broken
        else:
            sys.exit(0)  # Success
            
    except Exception as e:
        print(f"Error during validation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
