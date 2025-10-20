#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import re
from pathlib import Path
from typing import List, Tuple, Dict, Set
import sys

# Import the YaraValidator from the provided script
# Assuming the provided script is saved as 'yara_validator_lib.py'
try:
    from yara_validator_lib import YaraValidator, YaraSource
except ImportError:
    print("Error: Could not import YaraValidator. Make sure 'yara_validator_lib.py' is in the same directory.")
    sys.exit(1)


def extract_rules_from_file(file_path: Path) -> List[Tuple[str, str]]:
    """
    Extracts individual YARA rules from a file.

    Args:
        file_path: Path to the YARA file.

    Returns:
        List of tuples: (rule_name, rule_source)
    """
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []
    
    # Extract imports from the beginning
    imports = []
    lines = content.split('\n')
    remaining_lines = []
    found_non_import = False
    
    for line in lines:
        stripped = line.strip()
        if not found_non_import and stripped.startswith('import '):
            imports.append(line)
        else:
            if stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
                found_non_import = True
            remaining_lines.append(line)
    
    import_block = '\n'.join(imports)
    if import_block and not import_block.endswith('\n'):
        import_block += '\n'
    
    rules_content = '\n'.join(remaining_lines)
    
    # Extract individual rules with their names
    rule_pattern = re.compile(
        r'(rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*[^\{]+)?\s*\{[^\}]*?\}(?:\s*\})*)',
        re.DOTALL
    )
    
    rules = []
    for match in rule_pattern.finditer(rules_content):
        rule_text = match.group(1).strip()
        rule_name = match.group(2)
        
        # Prepend imports to the rule
        full_rule = import_block + '\n' + rule_text if import_block else rule_text
        rules.append((rule_name, full_rule))
    
    return rules


def load_global_imports(imports_path: Path) -> str:
    """
    Loads global imports from a file.

    Args:
        imports_path: Path to the imports file.

    Returns:
        String containing import statements.
    """
    if not imports_path.exists():
        raise FileNotFoundError(f"Imports file not found: {imports_path}")
    
    try:
        content = imports_path.read_text(encoding='utf-8')
    except Exception as e:
        raise ValueError(f"Error reading imports file: {e}")
    
    # Extract only import statements
    lines = content.split('\n')
    import_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('import '):
            import_lines.append(line)
    
    if not import_lines:
        raise ValueError("No import statements found in imports file")
    
    imports_content = '\n'.join(import_lines)
    if not imports_content.endswith('\n'):
        imports_content += '\n'
    
    return imports_content


def find_yara_files(path: Path) -> List[Path]:
    """
    Finds all YARA files in a directory or returns a single file.

    Args:
        path: Path to a directory or file.

    Returns:
        List of YARA file paths.
    """
    if path.is_file():
        if path.suffix in ['.yar', '.yara']:
            return [path]
        else:
            print(f"Error: '{path}' is not a .yar or .yara file.")
            return []
    elif path.is_dir():
        yara_files = list(path.rglob("*.yar")) + list(path.rglob("*.yara"))
        return sorted(yara_files)
    else:
        print(f"Error: '{path}' is not a valid file or directory.")
        return []


def validate_rules(input_path: str, imports_file: str = None, 
                   failures_only: bool = False, accept_repairs: bool = False,
                   disk_buffering: bool = False, verbose: bool = False):
    """
    Main validation function using YaraValidator library.

    Args:
        input_path: Path to directory or file containing YARA rules.
        imports_file: Optional path to file containing import statements.
        failures_only: If True, only display failed validations.
        accept_repairs: If True, accept repaired rules.
        disk_buffering: If True, use disk buffering for validation.
        verbose: If True, display detailed information.
    """
    path = Path(input_path)
    
    # Load global imports if provided
    global_imports = None
    if imports_file:
        imports_path = Path(imports_file)
        try:
            global_imports = load_global_imports(imports_path)
            print(f"✓ Loaded global imports from: {imports_path}")
            if verbose:
                print(f"Imports content:\n{global_imports}")
        except (FileNotFoundError, ValueError) as e:
            print(f"✗ Error loading imports file: {e}")
            return
    
    # Find all YARA files
    yara_files = find_yara_files(path)
    
    if not yara_files:
        return
    
    print(f"\nFound {len(yara_files)} YARA file(s) to process\n")
    
    # Track results
    all_results = {
        'valid': [],
        'broken': [],
        'repaired': []
    }
    total_rules = 0
    
    # Process each file
    for file_path in yara_files:
        if verbose:
            print(f"\n{'='*70}")
            print(f"Processing: {file_path}")
            print('='*70)
        else:
            print(f"Processing: {file_path}")
        
        # Extract individual rules from the file
        rules = extract_rules_from_file(file_path)
        
        if not rules:
            print(f"  No rules found in {file_path}")
            continue
        
        total_rules += len(rules)
        
        # Validate each rule individually
        for rule_name, rule_source in rules:
            # Create a new validator for each rule
            validator = YaraValidator(
                disk_buffering=disk_buffering,
                auto_clear=True
            )
            
            # Prepend global imports if provided
            if global_imports:
                rule_source = global_imports + '\n' + rule_source
            
            # Add the rule to the validator
            validator.add_rule_source(
                source=rule_source,
                namespace='default',
                include_name=None
            )
            
            # Validate the rule
            valid, broken, repaired = validator.check_all(accept_repairs=accept_repairs)
            
            # Store results
            if valid:
                all_results['valid'].append({
                    'file': file_path,
                    'rule_name': rule_name,
                    'yara_source': valid[0]
                })
                if verbose:
                    print(f"  ✓ [{rule_name}] Valid")
            elif repaired:
                all_results['repaired'].append({
                    'file': file_path,
                    'rule_name': rule_name,
                    'yara_source': repaired[0]
                })
                if verbose:
                    print(f"  ⚠ [{rule_name}] Repaired")
            elif broken:
                all_results['broken'].append({
                    'file': file_path,
                    'rule_name': rule_name,
                    'yara_source': broken[0]
                })
                if verbose:
                    print(f"  ✗ [{rule_name}] Failed - {broken[0].error_data}")
            
            # Clean up
            validator.clear_tmp()
    
    # Print results
    print_results(all_results, failures_only, verbose, total_rules)


def print_results(results: Dict, failures_only: bool, verbose: bool, total_rules: int):
    """
    Prints validation results.

    Args:
        results: Dictionary containing validation results.
        failures_only: If True, only print failures.
        verbose: If True, print detailed information.
        total_rules: Total number of rules processed.
    """
    valid_count = len(results['valid'])
    broken_count = len(results['broken'])
    repaired_count = len(results['repaired'])
    
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    print(f"Total rules processed: {total_rules}")
    print(f"✓ Valid rules: {valid_count}")
    print(f"⚠ Repaired rules: {repaired_count}")
    print(f"✗ Failed rules: {broken_count}")
    print("="*70)
    
    # Print detailed results
    if not failures_only:
        if results['valid']:
            print("\n" + "="*70)
            print("VALID RULES")
            print("="*70)
            for item in results['valid']:
                print(f"\n✓ {item['rule_name']}")
                print(f"   File: {item['file']}")
                if verbose:
                    print(f"   Status: {item['yara_source'].status}")
        
        if results['repaired']:
            print("\n" + "="*70)
            print("REPAIRED RULES")
            print("="*70)
            for item in results['repaired']:
                print(f"\n⚠ {item['rule_name']}")
                print(f"   File: {item['file']}")
                print(f"   Original Error: {item['yara_source'].error_data}")
                if verbose:
                    print(f"\n   Original Source:")
                    for line in item['yara_source'].source.splitlines()[:10]:
                        print(f"      {line}")
                    print(f"\n   Repaired Source:")
                    for line in item['yara_source'].repaired_source.splitlines()[:10]:
                        print(f"      {line}")
    
    if results['broken']:
        print("\n" + "="*70)
        print("FAILED RULES")
        print("="*70)
        for item in results['broken']:
            print(f"\n✗ {item['rule_name']}")
            print(f"   File: {item['file']}")
            print(f"   Error: {item['yara_source'].error_data}")
            if verbose:
                print(f"\n   Rule Source:")
                for line in item['yara_source'].source.splitlines()[:10]:
                    print(f"      {line}")
    
    if not results['broken']:
        print("\n🎉 All rules validated successfully!")


def main():
    """
    Main function to handle command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Validate YARA rules using YaraValidator library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i /path/to/rules/directory
  %(prog)s -i /path/to/single_rule.yar
  %(prog)s -i /path/to/rules/directory --failures-only
  %(prog)s -i /path/to/rules/directory --imports /path/to/imports.yar
  %(prog)s -i /path/to/rules/directory --imports /path/to/imports.yar --verbose
  %(prog)s -i /path/to/rules/directory --accept-repairs --disk-buffering
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        help="Path to YARA file or directory containing YARA files",
        required=True
    )
    
    parser.add_argument(
        "--imports",
        help="Path to file containing import statements to prepend to all rules",
        required=False
    )
    
    parser.add_argument(
        "--failures-only",
        action="store_true",
        help="Only display failed validations"
    )
    
    parser.add_argument(
        "--accept-repairs",
        action="store_true",
        help="Accept automatically repaired rules"
    )
    
    parser.add_argument(
        "--disk-buffering",
        action="store_true",
        help="Use disk buffering for validation (required for some YARA versions)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    validate_rules(
        input_path=args.input,
        imports_file=args.imports,
        failures_only=args.failures_only,
        accept_repairs=args.accept_repairs,
        disk_buffering=args.disk_buffering,
        verbose=args.verbose
    )


if __name__ == "__main__":
    main()
