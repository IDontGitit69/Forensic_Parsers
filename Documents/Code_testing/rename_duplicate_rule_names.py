import os
import re
import argparse
from collections import defaultdict

# Regex to detect rule names (matches your grep command)
RULE_NAME_RE = re.compile(r'^\s*rule\s+([A-Za-z0-9_]+)', re.MULTILINE)

def find_duplicate_rule_names(input_dir):
    """
    Scan all files in the directory to find rule names and detect duplicates.
    Returns a set of names that appear more than once.
    """
    name_counts = defaultdict(int)

    for fname in os.listdir(input_dir):
        if not fname.lower().endswith(('.yar', '.yara')):
            continue
        path = os.path.join(input_dir, fname)
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            continue

        names = RULE_NAME_RE.findall(content)
        for name in names:
            name_counts[name] += 1

    duplicates = {name for name, count in name_counts.items() if count > 1}
    return duplicates

def rename_duplicates_in_file(file_path, duplicate_names):
    """
    Rename rules in a single file that are in the duplicate_names set.
    Appends _1, _2, etc. to subsequent occurrences.
    Returns the modified content and the set of renamed rules.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    name_counters = defaultdict(int)
    renamed_rules_in_file = set()

    def replace_rule_name(match):
        rule_name = match.group(1)
        if rule_name in duplicate_names:
            if name_counters[rule_name] == 0:
                # Keep first occurrence
                name_counters[rule_name] += 1
                return match.group(0)
            else:
                # Rename subsequent duplicates
                new_name = f"{rule_name}_{name_counters[rule_name]}"
                name_counters[rule_name] += 1
                renamed_rules_in_file.add(rule_name)
                return match.group(0).replace(rule_name, new_name, 1)
        else:
            return match.group(0)

    new_content = RULE_NAME_RE.sub(replace_rule_name, content)
    return new_content, renamed_rules_in_file

def rename_duplicate_rule_names(input_dir, output_file):
    duplicates = find_duplicate_rule_names(input_dir)
    if not duplicates:
        print("No duplicate rule names found.")
        return

    print("Duplicate rule names detected (will be renamed):")
    for name in sorted(duplicates):
        print(f" - {name}")

    combined_content = []

    for fname in sorted(os.listdir(input_dir)):
        if not fname.lower().endswith(('.yar', '.yara')):
            continue
        path = os.path.join(input_dir, fname)
        modified_content, renamed_in_file = rename_duplicates_in_file(path, duplicates)
        combined_content.append(modified_content)

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("\n\n".join(combined_content))

    print(f"\n✅ Renamed master YARA file written to: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rename duplicate YARA rule names using grep-style detection.")
    parser.add_argument("input_dir", help="Directory containing .yar/.yara files")
    parser.add_argument("--output", "-o", default="renamed_master_rules.yar", help="Output master YARA file")
    args = parser.parse_args()

    rename_duplicate_rule_names(args.input_dir, args.output)
