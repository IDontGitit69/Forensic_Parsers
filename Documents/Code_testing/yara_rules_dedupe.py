#!/usr/bin/env python3
import sys, re

def extract_rules(filename):
    with open(filename, 'r') as f:
        content = f.read()
    # Split on YARA 'rule ' or Sigma 'title: '
    rules = re.split(r'(?=^rule\s|\ntitle:\s)', content, flags=re.MULTILINE)
    return [r.strip() for r in rules if r.strip()]

def dedupe_rules(infile, outfile):
    seen = set()
    deduped = []
    for rule in extract_rules(infile):
        if rule not in seen:
            seen.add(rule)
            deduped.append(rule)
    with open(outfile, 'w') as out:
        out.write("\n\n".join(deduped))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: dedupe_rules.py merged_file deduped_file")
        sys.exit(1)
    dedupe_rules(sys.argv[1], sys.argv[2])
