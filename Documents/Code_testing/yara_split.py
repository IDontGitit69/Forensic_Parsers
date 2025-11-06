#!/usr/bin/env python3
import os
import re
import sys
import argparse

def split_yara_rules_in_dir(base_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    # Pattern to detect start of YARA rules
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

    header_lines = []
    rule_blocks = []
    current_rule = []

    for line in lines:
        if rule_pattern.match(line):
            if current_rule:
                rule_blocks.append(header_lines + current_rule)
                current_rule = []
                header_lines = []
            current_rule.append(line)
        else:
            if not current_rule:
                header_lines.append(line)
            else:
                current_rule.append(line)

    if current_rule:
        rule_blocks.append(header_lines + current_rule)

    for i, rule in enumerate(rule_blocks, start=1):
        rule_text = "".join(rule)
        match = re.search(r'(?i)rule\s+([A-Za-z0-9_]+)', rule_text)
        rule_name = match.group(1) if match else f"rule_{i}"

        output_file = os.path.join(output_dir, f"{rule_name}.yar")

        counter = 1
        while os.path.exists(output_file):
            output_file = os.path.join(output_dir, f"{rule_name}_{counter}.yar")
            counter += 1

        with open(output_file, "w", encoding="utf-8") as out:
            out.write(rule_text.strip() + "\n")
        print(f"    → Saved {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Recursively split YARA files into individual rule files."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the input directory containing .yar or .yara files."
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Path to the output directory where split rules will be saved."
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input):
        print(f"Error: {args.input} is not a valid directory.")
        sys.exit(1)

    split_yara_rules_in_dir(args.input, args.output)
    print(f"\n✅ Done! Split YARA rules are saved in: {args.output}")


if __name__ == "__main__":
    main()
