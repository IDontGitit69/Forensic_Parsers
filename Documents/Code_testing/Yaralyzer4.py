import argparse
import re
from collections import Counter
from pathlib import Path
from tqdm import tqdm


def list_yar_files(directory):
    """
    Recursively lists all .yar and .yara files in the given directory and subdirectories.

    Args:
        directory (Path): The path to the directory to scan.

    Returns:
        list: A list of Path objects for files ending with '.yar' or '.yara'.
    """
    directory = Path(directory)
    yar_files = list(directory.rglob("*.yar")) + list(directory.rglob("*.yara"))
    return yar_files


def extract_rule_names(file_content):
    """
    Extracts all rule names from YARA file content.

    Args:
        file_content (str): The content of a YARA file.

    Returns:
        list: A list of rule names found in the content.
    """
    return re.findall(r"rule\s+([a-zA-Z0-9_]+)", file_content)


def read_yara_file(yar_file):
    """
    Reads a YARA file with UTF-8 encoding and handles errors.

    Args:
        yar_file (Path): Path to the YARA file.

    Returns:
        str or None: The file content if successful, None otherwise.
    """
    try:
        return yar_file.read_text(encoding='utf-8')
    except Exception as e:
        print(f"Error reading {yar_file}: {e}")
        return None


def track_rule_sources(file_content, yar_file, rule_sources):
    """
    Updates the rule_sources dictionary with rule names from a file.

    Args:
        file_content (str): The content of the YARA file.
        yar_file (Path): Path to the YARA file.
        rule_sources (dict): Dictionary mapping rule names to source files.
    """
    rule_names = extract_rule_names(file_content)
    for rule_name in rule_names:
        if rule_name not in rule_sources:
            rule_sources[rule_name] = []
        rule_sources[rule_name].append(yar_file.name)


def combine_rules(yar_files):
    """
    Reads and combines content of YARA files into a single string.

    Args:
        yar_files (list): A list of Path objects for .yar files to combine.

    Returns:
        tuple: A tuple containing:
            - str: Combined content of all YARA files, separated by newlines.
            - dict: Dictionary mapping rule names to their source filenames.
    """
    combined_rules = []
    rule_sources = {}
    
    for yar_file in tqdm(yar_files, desc="Reading YARA files"):
        file_content = read_yara_file(yar_file)
        if file_content:
            track_rule_sources(file_content, yar_file, rule_sources)
            combined_rules.append(file_content)
    
    return "\n".join(combined_rules) + "\n", rule_sources


def create_rule_replacement(match):
    """
    Helper function for prefixing rule names with 'A_'.

    Args:
        match (re.Match): Regular expression match object.

    Returns:
        str: The replacement string with prefixed rule name.
    """
    rule_name = match.group(1)
    tags_metadata = match.group(2) or ""
    opening_brace = match.group(3)
    
    if rule_name.startswith("A_"):
        return match.group(0)
    else:
        return f"rule A_{rule_name}{tags_metadata}{opening_brace}"


def prefix_rule_names(rules_string):
    """
    Prefixes all YARA rule names in a string with 'A_' if not already prefixed.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with rule names prefixed.
    """
    rule_pattern = re.compile(r"rule\s+([a-zA-Z0-9_]+)(\s*:\s*[^\{]+)?(\s*\{)", re.MULTILINE)
    return rule_pattern.sub(create_rule_replacement, rules_string)


def extract_rule_body(rule_content):
    """
    Extracts the body of a YARA rule (content after the first '{').

    Args:
        rule_content (str): The full content of a YARA rule.

    Returns:
        str or None: The rule body, or None if not found.
    """
    content_start = rule_content.find('{')
    if content_start != -1:
        return rule_content[content_start:].strip()
    return None


def remove_duplicate_rules(rules_string):
    """
    Removes duplicate rules based on their content.

    Identifies rules and removes duplicates based on the rule body.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: A string containing only unique YARA rules.
    """
    rule_pattern = re.compile(
        r"rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*[^\{]+)?\s*\{.*?(?=\nrule\s+[a-zA-Z0-9_]+|\Z)", 
        re.DOTALL
    )
    all_rule_matches = list(rule_pattern.finditer(rules_string))
    total_rules_found = len(all_rule_matches)

    unique_rules = {}
    for rule_match in all_rule_matches:
        rule_content = rule_match.group(0)
        rule_body = extract_rule_body(rule_content)
        
        if rule_body and rule_body not in unique_rules:
            unique_rules[rule_body] = rule_content

    num_unique_rules = len(unique_rules)
    num_duplicate_rules = total_rules_found - num_unique_rules
    print(f"Number of duplicate rules found: {num_duplicate_rules}")

    return "\n".join(unique_rules.values())


def find_duplicate_names(rules_string):
    """
    Identifies duplicate rule names in the rules string.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        tuple: (rule_name_counts dict, list of duplicate names)
    """
    rule_names = re.findall(r"rule\s+([a-zA-Z0-9_]+)", rules_string)
    rule_name_counts = Counter(rule_names)
    duplicate_names = [name for name, count in rule_name_counts.items() if count > 1]
    return rule_name_counts, duplicate_names


def print_duplicate_info(duplicate_names, rule_name_counts, rule_sources):
    """
    Prints information about duplicate rule names found.

    Args:
        duplicate_names (list): List of duplicate rule names.
        rule_name_counts (Counter): Count of each rule name occurrence.
        rule_sources (dict): Dictionary mapping rule names to source files.
    """
    num_duplicates = len(duplicate_names)
    print(f"\nNumber of duplicate rule names found: {num_duplicates}")
    
    if duplicate_names:
        print("Duplicate rule names found in these files (kept first occurrence):")
        for dup_name in duplicate_names:
            source_files = rule_sources.get(dup_name, ["Unknown"])
            count = rule_name_counts[dup_name]
            print(f"  - {dup_name} (appeared {count} times, found in: {', '.join(source_files)})")


def rename_duplicates_efficiently(rules_string, duplicate_names):
    """
    Efficiently renames duplicate rule names using list-based reconstruction.
    
    This is O(n) instead of O(n²) by building the result as a list and only
    processing the string once per duplicate name.

    Args:
        rules_string (str): A string containing YARA rules.
        duplicate_names (list): List of duplicate rule names to process.

    Returns:
        str: The modified string with renamed duplicates.
    """
    modified_rules = rules_string
    
    for dup_name in tqdm(duplicate_names, desc="Handling duplicate names"):
        # Find all matches for the current duplicate rule name
        pattern = r"(rule\s+)(" + re.escape(dup_name) + r"\b)"
        matches = list(re.finditer(pattern, modified_rules))
        
        if len(matches) <= 1:
            continue
        
        # Build result using list for O(n) performance
        result_parts = []
        last_end = 0
        
        for i, match in enumerate(matches):
            # Add the part before this match
            result_parts.append(modified_rules[last_end:match.start(2)])
            
            # Add the rule name (with suffix if not the first occurrence)
            if i == 0:
                result_parts.append(dup_name)
            else:
                result_parts.append(f"{dup_name}_{i}")
            
            last_end = match.end(2)
        
        # Add the remaining part
        result_parts.append(modified_rules[last_end:])
        modified_rules = "".join(result_parts)
    
    return modified_rules


def handle_duplicate_rule_names(rules_string, rule_sources):
    """
    Finds duplicate rule names and appends incremental numbers to duplicates.

    Args:
        rules_string (str): A string containing YARA rules with potentially
                            duplicate rule names.
        rule_sources (dict): Dictionary mapping rule names to their source filenames.

    Returns:
        str: The modified string with duplicate rule names suffixed with numbers.
    """
    rule_name_counts, duplicate_names = find_duplicate_names(rules_string)
    print_duplicate_info(duplicate_names, rule_name_counts, rule_sources)
    
    if not duplicate_names:
        return rules_string
    
    return rename_duplicates_efficiently(rules_string, duplicate_names)


def extract_unique_imports(rules_string):
    """
    Extracts all unique import statements from the rules string.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        tuple: (list of unique imports, list of duplicate imports)
    """
    import_statements = re.findall(r'^import\s+".*?"', rules_string, re.MULTILINE)
    
    seen = set()
    unique_imports = []
    duplicate_imports = []
    
    for imp in import_statements:
        if imp not in seen:
            seen.add(imp)
            unique_imports.append(imp)
        else:
            duplicate_imports.append(imp)
    
    return unique_imports, duplicate_imports


def print_duplicate_imports(duplicate_imports):
    """
    Prints information about duplicate import statements.

    Args:
        duplicate_imports (list): List of duplicate import statements.
    """
    if duplicate_imports:
        print(f"\nNumber of duplicate import statements removed: {len(duplicate_imports)}")
        print("Discarded duplicate imports:")
        for imp in set(duplicate_imports):
            print(f"  - {imp}")


def rebuild_rules_with_imports(unique_imports, cleaned_rules):
    """
    Rebuilds the rules string with imports at the top.

    Args:
        unique_imports (list): List of unique import statements.
        cleaned_rules (str): Rules content without import statements.

    Returns:
        str: Final rules string with imports at the top.
    """
    import_string = "\n".join(unique_imports)
    
    if import_string and cleaned_rules:
        return import_string + "\n\n" + cleaned_rules
    elif import_string:
        return import_string
    else:
        return cleaned_rules


def move_import_statements(rules_string):
    """
    Extracts all unique import statements and places them at the beginning of the content.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with unique import statements moved to the top.
    """
    unique_imports, duplicate_imports = extract_unique_imports(rules_string)
    print_duplicate_imports(duplicate_imports)
    
    # Remove import statements from the rules
    cleaned_rules = re.sub(r'^import\s+".*?"\s*\n?', '', rules_string, flags=re.MULTILINE)
    
    return rebuild_rules_with_imports(unique_imports, cleaned_rules)


def create_output_directory(directory):
    """
    Creates the output directory if it doesn't exist.

    Args:
        directory (Path): The path to the directory to create.
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


def write_rules_file(directory, filename, rules_string):
    """
    Writes the processed rules to a file in the specified directory.

    Args:
        directory (Path): The directory where the file should be saved.
        filename (str): The name of the output file.
        rules_string (str): The string containing the processed YARA rules.
    """
    output_file_path = Path(directory) / filename
    try:
        output_file_path.write_text(rules_string, encoding='utf-8')
    except IOError as e:
        print(f"Error: Could not write to file {output_file_path}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing to {output_file_path}: {e}")


def count_final_rules(final_rules):
    """
    Counts the final number of rules in the processed output.

    Args:
        final_rules (str): The final processed rules string.

    Returns:
        int: The number of rules found.
    """
    return len(re.findall(r"^rule\s+[a-zA-Z0-9_]+", final_rules, re.MULTILINE))


def process_yara_rules(input_directory, output_directory, output_filename):
    """
    Main processing pipeline for YARA rules.

    Args:
        input_directory (str): Input directory containing YARA files.
        output_directory (str): Output directory for the master file.
        output_filename (str): Name of the output file.
    """
    # Find all YARA files
    yar_files = list_yar_files(input_directory)
    if not yar_files:
        print(f"No .yar or .yara files found in {input_directory} or its subdirectories")
        return

    print(f"Found {len(yar_files)} YARA file(s)")
    
    # Process rules through the pipeline
    combined_rules, rule_sources = combine_rules(yar_files)
    prefixed_rules = prefix_rule_names(combined_rules)
    cleaned_rules = remove_duplicate_rules(prefixed_rules)
    cleaned_rules_with_unique_names = handle_duplicate_rule_names(cleaned_rules, rule_sources)
    final_rules = move_import_statements(cleaned_rules_with_unique_names)
    
    # Write output
    create_output_directory(output_directory)
    write_rules_file(output_directory, output_filename, final_rules)
    
    # Report results
    final_rule_count = count_final_rules(final_rules)
    print(f"\nFinal number of rules: {final_rule_count}")
    print(f"Processed rules saved to {Path(output_directory) / output_filename}")


def main():
    """
    Orchestrates the YARA rule processing workflow.

    Handles command-line arguments and initiates processing.
    """
    parser = argparse.ArgumentParser(description="Process YARA rules from a directory recursively.")
    parser.add_argument("-i", "--input-dir", help="Input directory containing YARA rule files", required=True)
    parser.add_argument("-o", "--output-file", help="Output filename for the master rule file", default="Master_Rules.yar")
    parser.add_argument("-d", "--output-dir", help="Output directory where the master rule file will be saved", default="Prod_Rules")

    args = parser.parse_args()

    # Validate input directory
    if not Path(args.input_dir).is_dir():
        print(f"Error: Input directory not found at {args.input_dir}")
        return

    process_yara_rules(args.input_dir, args.output_dir, args.output_file)


if __name__ == "__main__":
    main()
