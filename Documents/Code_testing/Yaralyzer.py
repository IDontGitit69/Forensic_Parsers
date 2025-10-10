import argparse
import os
import re
from collections import Counter
from tqdm import tqdm

def list_yar_files(directory):
    """
    Lists all .yar files in the given directory.

    Args:
        directory (str): The path to the directory to scan.

    Returns:
        list: A list of filenames ending with '.yar'.
    """
    all_files = os.listdir(directory)
    yar_files = [f for f in all_files if f.endswith('.yar')]
    return yar_files

def combine_rules(directory, yar_files):
    """
    Reads and combines content of YARA files into a single string.

    Args:
        directory (str): The path to the directory containing the YARA files.
        yar_files (list): A list of .yar filenames to combine.

    Returns:
        str: A single string containing the combined content of all YARA files,
             separated by newlines.
    """
    combined_rules = ""
    for yar_file in tqdm(yar_files, desc="Reading YARA files"):
        file_path = os.path.join(directory, yar_file)
        try:
            with open(file_path, 'r') as f:
                combined_rules += f.read() + "\n"
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
        except Exception as e:
            print(f"An error occurred while reading {file_path}: {e}")
    return combined_rules

def prefix_rule_names(rules_string):
    """
    Prefixes all YARA rule names in a string with 'A_'.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with rule names prefixed.
    """
    # Find all rule names using regex: 'rule ' followed by one or more
    # alphanumeric characters or underscores.
    rule_names = re.findall(r"rule\s+([a-zA-Z0-9_]+)", rules_string)
    modified_rules = rules_string
    for rule_name in rule_names:
        # Use word boundaries (\b) to ensure we only replace the rule name itself
        # and not parts of other words or strings.
        modified_rules = re.sub(r"rule\s+" + re.escape(rule_name) + r"\b", f"rule A_{rule_name}", modified_rules)
    return modified_rules

def remove_duplicate_rules(rules_string):
    """
    Removes duplicate rules based on their content.

    Identifies rules by looking for 'rule RuleName {' and extracts the content
    until the next 'rule ' or the end of the string. Duplicate rules are
    removed based on the body of the rule (content after '{').

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: A string containing only unique YARA rules.
    """
    # Regex to find individual rules: 'rule ' followed by name, then '{',
    # then any characters non-greedily (.*?) until the next 'rule ' or end of string (\Z).
    rule_pattern = re.compile(r"rule\s+([a-zA-Z0-9_]+)\s*\{.*?(?=\nrule\s+[a-zA-Z0-9_]+|\Z)", re.DOTALL)
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

def handle_duplicate_rule_names(rules_string):
    """
    Finds duplicate rule names and appends incremental numbers to duplicates.

    Args:
        rules_string (str): A string containing YARA rules with potentially
                            duplicate rule names.

    Returns:
        str: The modified string with duplicate rule names suffixed with
             incremental numbers (e.g., _1, _2).
    """
    # Find all rule names
    rule_names_in_cleaned = re.findall(r"rule\s+([a-zA-Z0-9_]+)", rules_string)
    # Count occurrences of each rule name
    rule_name_counts = Counter(rule_names_in_cleaned)
    # Identify names that appear more than once
    duplicate_rule_names = [name for name, count in rule_name_counts.items() if count > 1]
    num_duplicate_rule_names_found = len(duplicate_rule_names)
    print(f"Number of duplicate rule names found: {num_duplicate_rule_names_found}")

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
    Extracts all import statements and places them at the beginning of the content.

    Args:
        rules_string (str): A string containing YARA rules.

    Returns:
        str: The modified string with import statements moved to the top.
    """
    # Find all lines starting with 'import "..."'
    import_statements = re.findall(r'^import\s+".*?"', rules_string, re.MULTILINE)
    # Join the found import statements into a single string
    import_string = "\n".join(import_statements)
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

    args = parser.parse_args()

    input_directory = args.input_dir
    output_directory = 'Prod_Rules' # Keep this fixed as per the original task
    output_filename = args.output_file

    # Check if input directory exists
    if not os.path.isdir(input_directory):
        print(f"Error: Input directory not found at {input_directory}")
        return


    yar_files = list_yar_files(input_directory)
    if not yar_files:
        print(f"No .yar files found in {input_directory}")
        return

    combined_rules = combine_rules(input_directory, yar_files)
    prefixed_rules = prefix_rule_names(combined_rules)
    cleaned_rules = remove_duplicate_rules(prefixed_rules)
    cleaned_rules_with_unique_names = handle_duplicate_rule_names(cleaned_rules)
    final_rules = move_import_statements(cleaned_rules_with_unique_names)
    create_output_directory(output_directory)
    write_rules_file(output_directory, output_filename, final_rules)

    # Count the final number of rules by finding all lines starting with "rule "
    final_rule_count = len(re.findall(r"^rule\s+[a-zA-Z0-9_]+", final_rules, re.MULTILINE))
    print(f"Final number of rules: {final_rule_count}")

    print(f"Processed rules saved to {os.path.join(output_directory, output_filename)}")


if __name__ == "__main__":
    main()
