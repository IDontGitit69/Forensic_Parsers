#!/usr/bin/env python3
import os
import re
import sys

def split_yara_rules_in_dir(base_dir: str, output_dir: str = None):
    # Default output directory
    if output_dir is None:
        output_dir = os.path.join(base_dir, "split_rules")
    os.makedirs(output_dir, exist_ok=True)

    # Pattern to match the start of a YARA rule
    rule_pattern = re.compile(r'(?i)^\s*(private\s+)?rule\s+\w+')

    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.lower().endswith((".yar", ".yara")):
                full_path = os.path.join(root, file)
                print(f"[+] Processing {full_path}")
                split_yara_file(full_path, output_dir, rule_pattern)


def split_yara_file(filepath: str, output_dir: str, rule_pattern):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    # Collect header/import/comment lines
    header_lines = []
    rule_blocks = []
    current_rule = []

    for line in lines:
        if rule_pattern.match(line):
            # Start of a new rule — save previous if exists
            if current_rule:
                rule_blocks.append(header_lines + current_rule)
                current_rule = []
                header_lines = []
            current_rule.append(line)
        else:
            if not current_rule:
                # Lines before first rule — keep as header (imports, comments, etc.)
                header_lines.append(line)
            else:
                current_rule.append(line)

    # Save last rule
    if current_rule:
        rule_blocks.append(header_lines + current_rule)

    # Write each rule to its own file
    for i, rule in enumerate(rule_blocks, start=1):
        rule_text = "".join(rule)

        # Try to extract rule name
        match = re.search(r'(?i)rule\s+([A-Za-z0-9_]+)', rule_text)
        rule_name = match.group(1) if match else f"rule_{i}"

        # Construct output filename
        output_file = os.path.join(output_dir, f"{rule_name}.yar")

        # Ensure unique filenames
        counter = 1
        while os.path.exists(output_file):
            output_file = os.path.join(output_dir, f"{rule_name}_{counter}.yar")
            counter += 1

        with open(output_file, "w", encoding="utf-8") as out:
            out.write(rule_text.strip() + "\n")
        print(f"    → Saved {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        base_dir = input("Enter the directory path containing YARA files: ").strip()
    else:
        base_dir = sys.argv[1]

    if not os.path.isdir(base_dir):
        print(f"Error: {base_dir} is not a valid directory.")
        sys.exit(1)

    split_yara_rules_in_dir(base_dir)
    print("\n✅ Done! Split YARA rules are saved in the 'split_rules' folder.")
