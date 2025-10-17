import argparse
import re
from pathlib import Path
from typing import List, Tuple, Dict
import yara


def extract_imports(content: str) -> Tuple[str, str]:
    """
    Extracts import statements from the beginning of YARA file content.

    Args:
        content: The full content of a YARA file.

    Returns:
        Tuple of (import_statements, remaining_content)
    """
    # Match all import statements at the beginning
    import_pattern = r'^\s*import\s+"[^"]+"\s*\n'
    imports = []
    remaining = content
    
    # Extract all consecutive import statements from the start
    while True:
        match = re.match(import_pattern, remaining, re.MULTILINE)
        if not match:
            break
        imports.append(match.group(0))
        remaining = remaining[match.end():]
    
    import_block = "".join(imports)
    return import_block, remaining


def extract_rules(content: str) -> List[str]:
    """
    Extracts individual YARA rules from content.

    Args:
        content: YARA file content without import statements.

    Returns:
        List of individual rule strings.
    """
    # Split on 'rule' keyword at the start of a line
    # This regex captures 'rule' and everything up to the next 'rule' or end of string
    rule_pattern = re.compile(
        r'rule\s+[a-zA-Z0-9_]+(?:\s*:\s*[^\{]+)?\s*\{.*?(?=\n\s*rule\s+[a-zA-Z0-9_]+|\Z)',
        re.DOTALL
    )
    
    rules = rule_pattern.findall(content)
    return [rule.strip() for rule in rules if rule.strip()]


def extract_rule_name(rule_string: str) -> str:
    """
    Extracts the rule name from a YARA rule string.

    Args:
        rule_string: A string containing a YARA rule.

    Returns:
        The rule name, or "Unnamed Rule" if not found.
    """
    # Match rule name with optional tags/metadata
    match = re.search(r"rule\s+([a-zA-Z0-9_]+)", rule_string)
    return match.group(1) if match else "Unnamed Rule"


def validate_rule(rule_string: str, rule_name: str) -> Tuple[bool, str]:
    """
    Validates a single YARA rule string.

    Args:
        rule_string: A string containing the YARA rule with imports.
        rule_name: The name of the rule being validated.

    Returns:
        Tuple of (success (bool), message (str)).
    """
    try:
        yara.compile(source=rule_string)
        return True, f"Rule '{rule_name}' validated successfully."
    except yara.Error as e:
        return False, f"Rule '{rule_name}' validation failed: {e}"
    except Exception as e:
        return False, f"Rule '{rule_name}' unexpected error: {e}"


def process_single_file(file_path: Path) -> List[Tuple[bool, str, str]]:
    """
    Reads a YARA file, extracts individual rules, and validates each rule.

    Args:
        file_path: Path to the YARA file.

    Returns:
        List of tuples: (success (bool), message (str), rule_name (str))
    """
    try:
        content = file_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return [(False, f"File not found: {file_path}", "N/A")]
    except Exception as e:
        return [(False, f"Error reading file: {e}", "N/A")]
    
    # Extract imports and remaining content
    import_block, rules_content = extract_imports(content)
    
    # Extract individual rules
    rules = extract_rules(rules_content)
    
    if not rules:
        return [(False, "No YARA rules found in file", "N/A")]
    
    # Validate each rule with imports prepended
    validation_results = []
    for rule_string in rules:
        rule_name = extract_rule_name(rule_string)
        # Prepend imports to each rule for validation
        full_rule = import_block + "\n" + rule_string if import_block else rule_string
        success, message = validate_rule(full_rule, rule_name)
        validation_results.append((success, message, rule_name))
    
    return validation_results


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


def print_summary(all_results: Dict[Path, List[Tuple[bool, str, str]]]):
    """
    Prints a summary of validation results.

    Args:
        all_results: Dictionary mapping file paths to validation results.
    """
    total_files = len(all_results)
    total_rules = sum(len(results) for results in all_results.values())
    total_success = sum(
        sum(1 for success, _, _ in results if success)
        for results in all_results.values()
    )
    total_failures = total_rules - total_success
    
    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print(f"Total files processed: {total_files}")
    print(f"Total rules validated: {total_rules}")
    print(f"Successful validations: {total_success}")
    print(f"Failed validations: {total_failures}")
    print("=" * 70)


def print_detailed_results(all_results: Dict[Path, List[Tuple[bool, str, str]]]):
    """
    Prints detailed validation results for each file.

    Args:
        all_results: Dictionary mapping file paths to validation results.
    """
    print("\n" + "=" * 70)
    print("DETAILED VALIDATION RESULTS")
    print("=" * 70)
    
    for file_path, results in all_results.items():
        print(f"\nFile: {file_path}")
        
        if not results:
            print("  No results to display.")
            continue
        
        for success, message, rule_name in results:
            status = "✓ SUCCESS" if success else "✗ FAILURE"
            print(f"  [{status}] {message}")


def print_failures_only(all_results: Dict[Path, List[Tuple[bool, str, str]]]):
    """
    Prints only the failed validations.

    Args:
        all_results: Dictionary mapping file paths to validation results.
    """
    print("\n" + "=" * 70)
    print("FAILED VALIDATIONS")
    print("=" * 70)
    
    has_failures = False
    for file_path, results in all_results.items():
        failures = [(msg, name) for success, msg, name in results if not success]
        
        if failures:
            has_failures = True
            print(f"\nFile: {file_path}")
            for message, rule_name in failures:
                print(f"  ✗ {message}")
    
    if not has_failures:
        print("\nNo failures found! All rules validated successfully.")


def process_yara_validation(input_path: str, failures_only: bool = False):
    """
    Main processing function to validate YARA rules.

    Args:
        input_path: Path to a directory or file containing YARA rules.
        failures_only: If True, only print failed validations.
    """
    path = Path(input_path)
    
    # Find all YARA files
    yara_files = find_yara_files(path)
    
    if not yara_files:
        return
    
    print(f"Found {len(yara_files)} YARA file(s) to process")
    
    # Process each file
    all_results = {}
    for file_path in yara_files:
        print(f"Processing: {file_path}")
        results = process_single_file(file_path)
        all_results[file_path] = results
    
    # Print results
    if failures_only:
        print_failures_only(all_results)
    else:
        print_detailed_results(all_results)
    
    print_summary(all_results)


def main():
    """
    Main function to handle command-line arguments and orchestrate validation.
    """
    parser = argparse.ArgumentParser(
        description="Validate YARA rules in a file or directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i /path/to/rules/directory
  %(prog)s -i /path/to/single_rule.yar
  %(prog)s -i /path/to/rules/directory --failures-only
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        help="Path to YARA file or directory containing YARA files",
        required=False
    )
    
    parser.add_argument(
        "--failures-only",
        action="store_true",
        help="Only display failed validations"
    )
    
    args = parser.parse_args()
    
    # Get input path from args or prompt user
    if args.input:
        input_path = args.input
    else:
        input_path = input("Enter the directory or file path to scan: ").strip()
    
    if not input_path:
        print("Error: No input path provided.")
        return
    
    process_yara_validation(input_path, args.failures_only)


if __name__ == "__main__":
    main()
