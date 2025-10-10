#!/usr/bin/env python3
"""
dedupe_yara_rules_preserve.py

Scan a directory of .yar/.yara files, extract complete YARA rules robustly
(preserving strings, comments, regexes), deduplicate by normalized full-text,
and write deduped output.

Usage:
    python dedupe_yara_rules_preserve.py /path/to/yara_dir --output deduped_master.yar
"""
import os
import re
import argparse
import hashlib
from datetime import datetime

# Header regex to find a rule declaration (supports optional modifiers like "private")
HEADER_RE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*rule\s+([A-Za-z0-9_]+)\b',
                       re.MULTILINE)

def find_matching_brace(text, open_idx):
    """
    Given an index of a '{' in text, find the index of the matching '}'.
    This function skips braces that appear inside:
      - double-quoted strings "..."
      - single-quoted strings '...'
      - single-line comments //...
      - multi-line comments /* ... */
      - slash-delimited regex literals /.../ (attempts to skip escaped slashes)
    Returns the index of the matching '}' or -1 if not found.
    """
    i = open_idx
    n = len(text)

    depth = 0
    in_dq = False   # double-quoted string
    in_sq = False   # single-quoted string
    in_sline = False
    in_mline = False

    while i < n:
        ch = text[i]
        nxt = text[i+1] if i+1 < n else ''

        # handle end of single-line comment
        if in_sline:
            if ch == '\n':
                in_sline = False
        elif in_mline:
            if ch == '*' and nxt == '/':
                in_mline = False
                i += 1  # skip the '/'
        elif in_dq:
            if ch == '\\':  # escape
                i += 1  # skip next char
            elif ch == '"':
                in_dq = False
        elif in_sq:
            if ch == '\\':
                i += 1
            elif ch == "'":
                in_sq = False
        else:
            # Not inside string/comment: detect start of comment/string/regex or braces
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
            elif ch == '/':
                # Attempt to detect a slash-delimited regex literal and skip it.
                # We only do this when it is NOT a comment start (we already checked).
                # Find closing unescaped slash.
                j = i + 1
                found = False
                while j < n:
                    if text[j] == '\\':
                        j += 2
                        continue
                    if text[j] == '/':
                        found = True
                        break
                    # allow newlines inside regex
                    j += 1
                if found:
                    i = j  # jump to the closing '/'
                # otherwise treat as a normal char
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i
        i += 1

    return -1

def extract_rules_from_text(text):
    """
    Extract full rule blocks from text using HEADER_RE then brace matching.
    Returns a list of (rule_text, rule_name) tuples in the order found.
    """
    rules = []
    pos = 0
    while True:
        m = HEADER_RE.search(text, pos)
        if not m:
            break
        start = m.start()
        # find first '{' after header
        open_idx = text.find('{', m.end())
        if open_idx == -1:
            # no body found; skip forward to avoid infinite loop
            pos = m.end()
            print(f"[WARN] Found rule header but no '{{' after it near pos {m.start()}; skipping")
            continue

        end_idx = find_matching_brace(text, open_idx)
        if end_idx == -1:
            print(f"[WARN] Couldn't find matching '}}' for rule starting at pos {start}; skipping")
            pos = open_idx + 1
            continue

        rule_text = text[start:end_idx+1]
        # extract name robustly from the captured header match
        name_match = re.search(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*rule\s+([A-Za-z0-9_]+)\b',
                               rule_text, re.MULTILINE)
        rule_name = name_match.group(1) if name_match else "<unknown>"
        rules.append((rule_text, rule_name))
        pos = end_idx + 1
    return rules

def normalize_rule(rule_text):
    # Normalize by collapsing all whitespace sequences to a single space.
    # We intentionally do NOT strip comments or other tokens so only whitespace changes
    # are ignored for deduplication.
    return re.sub(r'\s+', ' ', rule_text.strip())

def deduplicate_yara_dir(input_dir, output_file):
    unique_hashes = {}
    order = []
    total = 0
    duplicates = 0

    for fname in sorted(os.listdir(input_dir)):
        if not fname.lower().endswith(('.yar', '.yara')):
            continue
        path = os.path.join(input_dir, fname)
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                txt = fh.read()
        except Exception as e:
            print(f"[ERROR] Could not read {path}: {e}")
            continue

        rules = extract_rules_from_text(txt)
        if not rules:
            # maybe the file is just a single giant rule or none matched
            # attempt to recover entire file as one rule if it contains 'rule'
            if 'rule' in txt:
                print(f"[WARN] No rules extracted from {fname} by parser, but file contains 'rule' token.")
        for rule_text, rule_name in rules:
            total += 1
            norm = normalize_rule(rule_text)
            h = hashlib.sha256(norm.encode('utf-8')).hexdigest()
            if h not in unique_hashes:
                unique_hashes[h] = (rule_text, fname, rule_name)
                order.append(h)
            else:
                duplicates += 1
                first_seen_file = unique_hashes[h][1]
                print(f"[DUP] Duplicate rule '{rule_name}' in {fname} — identical to rule in {first_seen_file}")

    # Write deduplicated master
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write(f"// Deduplicated YARA rules\n")
        out.write(f"// Generated: {datetime.utcnow().isoformat()}Z\n")
        out.write(f"// Input dir: {os.path.abspath(input_dir)}\n")
        out.write(f"// Total rules scanned: {total}\n")
        out.write(f"// Unique rules written: {len(order)}\n")
        out.write("\n\n")
        for h in order:
            rule_text, fname, name = unique_hashes[h]
            out.write(rule_text.rstrip() + "\n\n")

    print("\nSummary:")
    print(f"  Total rules scanned : {total}")
    print(f"  Unique rules kept   : {len(order)}")
    print(f"  Duplicates skipped  : {duplicates}")
    print(f"\nWrote deduplicated master: {output_file}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deduplicate YARA rules by full content (preserve rule text).")
    ap.add_argument("input_dir", help="Directory containing .yar/.yara files")
    ap.add_argument("--output", "-o", default="deduped_master_rules.yar", help="Output master YARA file")
    args = ap.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"[ERROR] input_dir not found: {args.input_dir}")
        raise SystemExit(1)

    deduplicate_yara_dir(args.input_dir, args.output)
