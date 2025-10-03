#!/usr/bin/env python3
import sys, os, re, yara

def extract_rules_from_file(filepath):
    """Extracts YARA rule blocks from a file."""
    with open(filepath, 'r') as f:
        content = f.read()
    # Match YARA rules (start with 'rule <name>' and include the block)
    rules = re.split(r'(?=^rule\s)', content, flags=re.MULTILINE)
    return [r.strip() for r in rules if r.strip()]

def dedupe_and_validate_rules(input_files, output_file):
    seen = set()
    valid_rules = []

    for file in input_files:
        rules = extract_rules_from_file(file)
        for rule in rules:
            if rule not in seen:
                try:
                    # Attempt to compile this single rule to ensure it's valid
                    yara.compile(source=rule)
                    seen.add(rule)
                    valid_rules.append(rule)
                except yara.SyntaxError as e:
                    print(f"[!] Skipping invalid rule from {file}: {e}")

    with open(output_file, 'w') as out:
        out.write("\n\n".join(valid_rules))

    print(f"[+] Wrote {len(valid_rules)} unique, valid rules to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 compile_rules.py <output_file> <rule_file1> [<rule_file2> ...]")
        sys.exit(1)

    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    dedupe_and_validate_rules(input_files, output_file)
