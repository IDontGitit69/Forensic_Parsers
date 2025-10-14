import argparse
import os
import re
from collections import Counter
from tqdm import tqdm

def list_yar_files(directory):
    """
    Lists all .yar and .yara files in the given directory.

    Args:
        directory (str): The path to the directory to scan.

    Returns:
        list: A list of filenames ending with '.yar' or '.yara'.
    """
    all_files = os.listdir(directory)
    yar_files = [f for f in all_files if f.endswith('.yar') or f.endswith('.yara')]
    return yar_files

def combine_rules(directory, yar_files):
    """
    Reads and combines content of YARA files into a single string.

    Args:
        directory (str): The path to the directory containing the YARA files.
        yar_files (list): A list of .yar filenames to combine.

    Returns:
        tuple: A tuple containing:
            - str: A single string containing the combined content of all YARA files, separated by newlines.
            - dict: A dictionary mapping rule names to their source filenames.
    """
    combined_rules = ""
    rule_sources = {}  # Track which file each rule came from
    
    for yar_file in tqdm(yar_files, desc="Reading YARA files"):
        file_path = os.path.join(directory, yar_file)
        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
                # Extract rule names from this file
                rule_names = re.findall(r"rule\s+([a-zA-Z0-9_]+)", file_content)
                for rule_name in rule_names:
                    rule_sources[rule_name] = yar_file
                combined_rules += file_content + "\n"
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
        except Exception as e:
            print(f"An error occurred while reading {file_path}: {e}")
    return combined_rules, rule_sources

def prefix_rule_names(rules_string):
    """
    Prefixes all YARA rule names in a string with 'A_' if not already prefixed.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with rule names prefixed.
    """
    # Find all rule names using regex that handles tags/metadata after the rule name
    # This pattern captures: rule <name> (optional: tags/metadata) {
    rule_pattern = re.compile(r"rule\s+([a-zA-Z0-9_]+)(\s*:\s*[^\{]+)?(\s*\{)", re.MULTILINE)
    
    def replace_rule(match):
        rule_name = match.group(1)
        tags_metadata = match.group(2) or ""
        opening_brace = match.group(3)
        
        # Check if the rule name already starts with "A_"
        if rule_name.startswith("A_"):
            return match.group(0)  # Return unchanged
        else:
            return f"rule A_{rule_name}{tags_metadata}{opening_brace}"
    
    modified_rules = rule_pattern.sub(replace_rule, rules_string)
    return modified_rules

def remove_duplicate_rules(rules_string):
    """
    Removes duplicate rules based on their content.

    Identifies rules by looking for 'rule RuleName' (with optional tags/metadata)
    and extracts the content until the next 'rule ' or the end of the string.
    Duplicate rules are removed based on the body of the rule (content after '{').

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: A string containing only unique YARA rules.
    """
    # Updated regex to handle rule names with tags and metadata (e.g., "rule abc_defgh_1234 : rule description")
    # Pattern matches: rule <name> (optional: : tags/metadata) { ... } until next rule or end
    rule_pattern = re.compile(
        r"rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*[^\{]+)?\s*\{.*?(?=\nrule\s+[a-zA-Z0-9_]+|\Z)", 
        re.DOTALL
    )
    all_rule_matches = list(rule_pattern.finditer(rules_string))
    total_rules_found = len(all_rule_matches)

    unique_rules = {}
    for rule_match in all_rule_matches:
        rule_content = rule_match.group(0)
        # Find the start of the rule body (after the first '{')
        content_start = rule_content.find('{')
        if content_start != -1:
            rule_body = rule_content[content_start:].strip()
            # Use the rule body as the key to identify duplicates
            if rule_body not in unique_rules:
                unique_rules[rule_body] = rule_content

    num_unique_rules = len(unique_rules)
    num_duplicate_rules = total_rules_found - num_unique_rules
    print(f"Number of duplicate rules found: {num_duplicate_rules}")

    return "\n".join(unique_rules.values())

def handle_duplicate_rule_names(rules_string, rule_sources):
    """
    Finds duplicate rule names and appends incremental numbers to duplicates.

    Args:
        rules_string (str): A string containing YARA rules with potentially
                            duplicate rule names.
        rule_sources (dict): A dictionary mapping rule names to their source filenames.

    Returns:
        str: The modified string with duplicate rule names suffixed with
             incremental numbers (e.g., _1, _2).
    """
    # Find all rule names (updated to handle tags/metadata)
    rule_names_in_cleaned = re.findall(r"rule\s+([a-zA-Z0-9_]+)", rules_string)
    # Count occurrences of each rule name
    rule_name_counts = Counter(rule_names_in_cleaned)
    # Identify names that appear more than once
    duplicate_rule_names = [name for name, count in rule_name_counts.items() if count > 1]
    num_duplicate_rule_names_found = len(duplicate_rule_names)
    print(f"\nNumber of duplicate rule names found: {num_duplicate_rule_names_found}")
    
    if duplicate_rule_names:
        print("Discarded duplicate rule names (kept first occurrence):")
        for dup_name in duplicate_rule_names:
            source_file = rule_sources.get(dup_name, "Unknown")
            count = rule_name_counts[dup_name]
            print(f"  - {dup_name} (appeared {count} times, found in: {source_file})")

    modified_rules = rules_string
    modified_count = Counter() # To keep track of how many times we've modified a duplicate name

    # Iterate through the duplicate rule names and append incremental numbers to duplicates
    for dup_name in tqdm(duplicate_rule_names, desc="Handling duplicate names"):
        # Find all matches for the current duplicate rule name as a rule name
        matches = list(re.finditer(r"(rule\s+)(" + re.escape(dup_name) + r"\b)", modified_rules))

        # Iterate through matches and append incremental numbers.
        # Start from the second occurrence (index 1 in the matches list)
        for i, match in enumerate(matches[1:]):
            start, end = match.span(2)  # Get the start and end index of the rule name part
            # Calculate the correct position for insertion based on previous modifications
            # This is important because appending "_1", "_2", etc., shifts the indices
            # of subsequent matches.
            offset = sum(len("_" + str(j + 1)) for j in range(i))
            insert_pos = end + offset
            # Insert the incremental suffix
            modified_rules = modified_rules[:insert_pos] + "_" + str(i + 1) + modified_rules[insert_pos:]

    return modified_rules


def move_import_statements(rules_string):
    """
    Extracts all unique import statements and places them at the beginning of the content.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with unique import statements moved to the top.
    """
    # Find all lines starting with 'import "..."'
    import_statements = re.findall(r'^import\s+".*?"', rules_string, re.MULTILINE)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_imports = []
    duplicate_imports = []
    
    for imp in import_statements:
        if imp not in seen:
            seen.add(imp)
            unique_imports.append(imp)
        else:
            duplicate_imports.append(imp)
    
    if duplicate_imports:
        print(f"\nNumber of duplicate import statements removed: {len(duplicate_imports)}")
        print("Discarded duplicate imports:")
        for imp in set(duplicate_imports):
            print(f"  - {imp}")
    
    # Join the unique import statements into a single string
    import_string = "\n".join(unique_imports)
    # Remove the found import statements from the rest of the rules content
    # Use re.sub with re.MULTILINE flag and handle potential leading/trailing newlines
    cleaned_rules_without_imports = re.sub(r'^import\s+".*?"\s*\n?', '', rules_string, flags=re.MULTILINE)

    # Prepend the extracted import statements to the cleaned rules string
    # Ensure a newline separates imports from rules if both exist
    if import_string and cleaned_rules_without_imports:
        return import_string + "\n\n" + cleaned_rules_without_imports
    elif import_string:
        return import_string
    else:
        return cleaned_rules_without_imports

def create_output_directory(directory):
    """
    Creates the output directory if it doesn't exist.

    Args:
        directory (str): The path to the directory to create.
    """
    os.makedirs(directory, exist_ok=True)

def write_rules_file(directory, filename, rules_string):
    """
    Writes the processed rules to a file in the specified directory.

    Args:
        directory (str): The directory where the file should be saved.
        filename (str): The name of the output file.
        rules_string (str): The string containing the processed YARA rules.
    """
    output_file_path = os.path.join(directory, filename)
    try:
        with open(output_file_path, 'w') as f:
            f.write(rules_string)
    except IOError as e:
        print(f"Error: Could not write to file {output_file_path}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing to {output_file_path}: {e}")

def main():
    """
    Orchestrates the YARA rule processing workflow.

    Handles command-line arguments, calls the processing functions, and
    provides informative output.
    """
    parser = argparse.ArgumentParser(description="Process YARA rules from a directory.")
    parser.add_argument("-i", "--input-dir", help="Input directory containing YARA rule files", required=True)
    parser.add_argument("-o", "--output-file", help="Output filename for the master rule file", default="Master_Rules.yar")
    parser.add_argument("-d", "--output-dir", help="Output directory where the master rule file will be saved", default="Prod_Rules")

    args = parser.parse_args()

    input_directory = args.input_dir
    output_directory = args.output_dir
    output_filename = args.output_file

    # Check if input directory exists
    if not os.path.isdir(input_directory):
        print(f"Error: Input directory not found at {input_directory}")
        return


    yar_files = list_yar_files(input_directory)
    if not yar_files:
        print(f"No .yar files found in {input_directory}")
        return

    combined_rules, rule_sources = combine_rules(input_directory, yar_files)
    prefixed_rules = prefix_rule_names(combined_rules)
    cleaned_rules = remove_duplicate_rules(prefixed_rules, rule_sources)
    cleaned_rules_with_unique_names = handle_duplicate_rule_names(cleaned_rules, rule_sources)
    final_rules = move_import_statements(cleaned_rules_with_unique_names)
    create_output_directory(output_directory)
    write_rules_file(output_directory, output_filename, final_rules)

    # Count the final number of rules by finding all lines starting with "rule "
    final_rule_count = len(re.findall(r"^rule\s+[a-zA-Z0-9_]+", final_rules, re.MULTILINE))
    print(f"\nFinal number of rules: {final_rule_count}")

    print(f"Processed rules saved to {os.path.join(output_directory, output_filename)}")


if __name__ == "__main__":
    main()
