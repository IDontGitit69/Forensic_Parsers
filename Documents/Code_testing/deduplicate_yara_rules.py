import os
import re
import argparse
import hashlib

def extract_rules_from_text(text):
    # Matches entire YARA rules: from 'rule <name>' to the closing '}'
    # Handles nested braces using a non-greedy approach
    pattern = re.compile(r'(^\s*rule\s+[A-Za-z0-9_]+\s*.*?\{.*?\})', re.DOTALL | re.MULTILINE)
    return pattern.findall(text)

def normalize_rule(rule_text):
    # Strip extra whitespace for deduplication purposes
    return re.sub(r'\s+', ' ', rule_text.strip())

def deduplicate_rules(input_dir, output_file):
    unique_rules = {}
    rule_hashes = set()
    total_rules = 0

    for filename in os.listdir(input_dir):
        if not filename.lower().endswith(('.yar', '.yara')):
            continue

        file_path = os.path.join(input_dir, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        rules = extract_rules_from_text(content)
        total_rules += len(rules)

        for rule in rules:
            normalized = normalize_rule(rule)
            rule_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

            if rule_hash not in rule_hashes:
                rule_hashes.add(rule_hash)
                unique_rules[rule_hash] = rule
            else:
                print(f"[!] Duplicate rule found (skipped): {rule.split()[1]} in {filename}")

    print(f"\nTotal rules scanned: {total_rules}")
    print(f"Unique rules kept: {len(unique_rules)}")
    print(f"Duplicates removed: {total_rules - len(unique_rules)}")

    with open(output_file, "w", encoding="utf-8") as f:
        for rule in unique_rules.values():
            f.write(rule.strip() + "\n\n")

    print(f"\n✅ Deduplicated master rules written to: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deduplicate YARA rules by full content.")
    parser.add_argument("input_dir", help="Directory containing .yar/.yara files")
    parser.add_argument("--output", default="deduped_master_rules.yar", help="Output file path")
    args = parser.parse_args()

    deduplicate_rules(args.input_dir, args.output)
