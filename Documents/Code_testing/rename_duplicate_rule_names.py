import os
import re
import argparse
from collections import defaultdict

# Regex to find YARA rule headers
HEADER_RE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*rule\s+([A-Za-z0-9_]+)\b',
                       re.MULTILINE)

def find_matching_brace(text, open_idx):
    """Find the index of the matching '}' starting at open_idx."""
    i = open_idx
    n = len(text)
    depth = 0
    in_dq = False
    in_sq = False
    in_sline = False
    in_mline = False

    while i < n:
        ch = text[i]
        nxt = text[i+1] if i+1 < n else ''

        if in_sline:
            if ch == '\n':
                in_sline = False
        elif in_mline:
            if ch == '*' and nxt == '/':
                in_mline = False
                i += 1
        elif in_dq:
            if ch == '\\':
                i += 1
            elif ch == '"':
                in_dq = False
        elif in_sq:
            if ch == '\\':
                i += 1
            elif ch == "'":
                in_sq = False
        else:
            if ch == '/' and nxt == '/':
                in_sline = True
                i += 1
            elif ch == '/' and nxt == '*':
                in_mline = True
                i += 1
            elif ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1

def extract_rules(text):
    """Extract rules and return list of tuples: (rule_name, rule_text)"""
    rules = []
    pos = 0
    while True:
        m = HEADER_RE.search(text, pos)
        if not m:
            break
        start = m.start()
        open_idx = text.find('{', m.end())
        if open_idx == -1:
            pos = m.end()
            continue
        end_idx = find_matching_brace(text, open_idx)
        if end_idx == -1:
            pos = open_idx + 1
            continue
        rule_text = text[start:end_idx+1]
        rule_name = m.group(1)
        rules.append((rule_name, rule_text))
        pos = end_idx + 1
    return rules

def rename_duplicate_rule_names(input_dir, output_file):
    name_counts = defaultdict(int)
    renamed_rules = []
    duplicates_found = set()

    for fname in sorted(os.listdir(input_dir)):
        if not fname.lower().endswith(('.yar', '.yara')):
            continue
        path = os.path.join(input_dir, fname)
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        rules = extract_rules(content)
        for rule_name, rule_text in rules:
            if name_counts[rule_name] == 0:
                # first occurrence, keep original name
                renamed_rules.append(rule_text)
            else:
                # duplicate name found, rename
                new_name = f"{rule_name}_{name_counts[rule_name]}"
                duplicates_found.add(rule_name)
                # Replace the rule name in the text
                rule_text_renamed = re.sub(r'(^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*rule\s+)' + re.escape(rule_name) + r'\b',
                                           r'\1' + new_name,
                                           rule_text,
                                           flags=re.MULTILINE)
                renamed_rules.append(rule_text_renamed)
            name_counts[rule_name] += 1

    # Output renamed master file
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("\n\n".join(renamed_rules))
    print(f"✅ Renamed master YARA file written to: {output_file}")

    if duplicates_found:
        print("\nDuplicate rule names detected and renamed:")
        for name in sorted(duplicates_found):
            print(f" - {name}")
    else:
        print("\nNo duplicate rule names found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rename duplicate YARA rule names to avoid conflicts.")
    parser.add_argument("input_dir", help="Directory containing .yar/.yara files")
    parser.add_argument("--output", "-o", default="renamed_master_rules.yar", help="Output master YARA file")
    args = parser.parse_args()

    rename_duplicate_rule_names(args.input_dir, args.output)
