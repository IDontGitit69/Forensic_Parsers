#!/usr/bin/env python3
"""
YARA Rule Scope Metadata Injector

This script reads YARA rule bundles and adds 'scope = "memory"' to the meta
section of rules that contain "memonly" (case-insensitive) in their rule name.
"""

import argparse
import os
import re
import sys
from pathlib import Path


def parse_yara_file(content):
    """
    Parse a YARA file and return a list of rule dictionaries.
    Each dictionary contains the rule's full text and position information.
    """
    # Pattern to match YARA rules
    rule_pattern = re.compile(
        r'(rule\s+\w+\s*(?:\:\s*[\w\s]+)?\s*\{.*?\n\})',
        re.DOTALL | re.MULTILINE
    )
    
    rules = []
    for match in rule_pattern.finditer(content):
        rule_text = match.group(1)
        rules.append({
            'text': rule_text,
            'start': match.start(),
            'end': match.end()
        })
    
    return rules


def extract_rule_name(rule_text):
    """Extract the rule name from a YARA rule."""
    match = re.search(r'rule\s+(\w+)', rule_text)
    return match.group(1) if match else None


def has_memonly_in_name(rule_name):
    """Check if rule name contains 'memonly' (case-insensitive)."""
    return 'memonly' in rule_name.lower() if rule_name else False


def add_scope_to_meta(rule_text, scope_value="memory"):
    """
    Add or update scope field in the meta section of a YARA rule.
    If scope already exists with a different value, append with comma.
    """
    # Check if meta section exists
    meta_pattern = re.compile(r'(\s*meta\s*:\s*\n)', re.MULTILINE)
    meta_match = meta_pattern.search(rule_text)
    
    if meta_match:
        # Meta section exists - check if scope field already exists
        meta_start = meta_match.end()
        
        # Find the meta section boundaries (from meta: to the next section or strings/condition)
        remaining_after_meta = rule_text[meta_start:]
        next_section_match = re.search(r'\n\s*(strings|condition)\s*:', remaining_after_meta)
        
        if next_section_match:
            meta_end = meta_start + next_section_match.start()
            meta_content = rule_text[meta_start:meta_end]
        else:
            # No other section found, meta goes to end of rule
            meta_content = remaining_after_meta
            meta_end = len(rule_text)
        
        # Check if scope field already exists in meta
        scope_field_pattern = re.compile(r'(\s*)scope\s*=\s*"([^"]*)"', re.MULTILINE)
        scope_match = scope_field_pattern.search(meta_content)
        
        if scope_match:
            # Scope field exists - check if it already contains "memory"
            existing_scope = scope_match.group(2)
            
            if scope_value.lower() in existing_scope.lower():
                # Already has this scope value, no change needed
                return rule_text, False
            else:
                # Append new scope value
                new_scope_value = f'{existing_scope}, {scope_value}'
                
                # Replace the existing scope field
                old_scope_field = scope_match.group(0)
                indent = scope_match.group(1)
                new_scope_field = f'{indent}scope = "{new_scope_value}"'
                
                # Calculate absolute position in rule_text
                scope_abs_start = meta_start + scope_match.start()
                scope_abs_end = meta_start + scope_match.end()
                
                modified_rule = (rule_text[:scope_abs_start] + 
                               new_scope_field + 
                               rule_text[scope_abs_end:])
                
                return modified_rule, True
        else:
            # No scope field exists, add it as first field in meta
            remaining = rule_text[meta_start:]
            indent_match = re.match(r'^(\s+)', remaining)
            indent = indent_match.group(1) if indent_match else '        '
            
            new_field = f'{indent}scope = "{scope_value}"\n'
            modified_rule = rule_text[:meta_start] + new_field + rule_text[meta_start:]
            
            return modified_rule, True
    else:
        # No meta section exists, create one
        brace_pattern = re.compile(r'(rule\s+\w+\s*(?:\:\s*[\w\s]+)?\s*\{\s*\n)')
        brace_match = brace_pattern.search(rule_text)
        
        if brace_match:
            insert_pos = brace_match.end()
            meta_section = f'    meta:\n        scope = "{scope_value}"\n\n'
            modified_rule = rule_text[:insert_pos] + meta_section + rule_text[insert_pos:]
            
            return modified_rule, True
        else:
            # Fallback: couldn't parse rule structure
            print(f"Warning: Could not parse rule structure, skipping scope injection")
            return rule_text, False
    
    return rule_text, False


def process_yara_file(input_path, output_path):
    """
    Process a single YARA file: parse rules, add scope metadata to rules
    with 'memonly' in the name, and write to output file.
    """
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {input_path}: {e}")
        return False, 0
    
    # Extract any header content before the first rule
    first_rule_match = re.search(r'rule\s+\w+', content)
    if first_rule_match:
        header = content[:first_rule_match.start()]
        rules_content = content[first_rule_match.start():]
    else:
        header = ""
        rules_content = content
    
    # Parse all rules in the file
    rules = parse_yara_file(rules_content)
    
    if not rules:
        print(f"Warning: No rules found in {input_path}")
        return False, 0
    
    # Process each rule
    modified_rules = []
    modified_count = 0
    has_memonly_rules = False
    
    for rule_info in rules:
        rule_name = extract_rule_name(rule_info['text'])
        
        if has_memonly_in_name(rule_name):
            has_memonly_rules = True
            modified_rule, was_modified = add_scope_to_meta(rule_info['text'], "memory")
            modified_rules.append(modified_rule)
            
            if was_modified:
                print(f"  ✓ Added/updated scope for rule: {rule_name}")
                modified_count += 1
            else:
                print(f"  - Rule {rule_name} already has scope=memory")
        else:
            # No memonly in name, keep rule as-is
            modified_rules.append(rule_info['text'])
    
    # Only write to output if at least one rule had memonly
    if not has_memonly_rules:
        return True, 0  # Success but no modifications
    
    # Reconstruct the file
    output_content = header + '\n'.join(modified_rules)
    
    # Write to output file
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output_content)
        return True, modified_count
    except Exception as e:
        print(f"Error writing {output_path}: {e}")
        return False, 0


def main():
    parser = argparse.ArgumentParser(
        description='Add scope="memory" metadata to YARA rules containing "memonly" in rule name',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python add_scope_metadata.py --input-dir ./raw_rules --output-dir ./processed_rules

This will process all .yar files and add scope="memory" to rules with "memonly" in their name.
        """
    )
    
    parser.add_argument(
        '--input-dir',
        required=True,
        help='Directory containing YARA rule files (.yar)'
    )
    
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Directory to save processed YARA rule files'
    )
    
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    
    # Validate input directory
    if not input_dir.exists():
        print(f"Error: Input directory does not exist: {input_dir}")
        sys.exit(1)
    
    if not input_dir.is_dir():
        print(f"Error: Input path is not a directory: {input_dir}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all .yar files
    yar_files = list(input_dir.glob('*.yar'))
    
    if not yar_files:
        print(f"Warning: No .yar files found in {input_dir}")
        sys.exit(0)
    
    print(f"Found {len(yar_files)} YARA rule files to process\n")
    
    # Process each file
    success_count = 0
    total_rules_modified = 0
    
    for yar_file in yar_files:
        output_file = output_dir / yar_file.name
        
        print(f"Processing: {yar_file.name}")
        
        success, modified_count = process_yara_file(yar_file, output_file)
        
        if success:
            success_count += 1
            total_rules_modified += modified_count
            
            if modified_count > 0:
                print(f"  → Modified {modified_count} rule(s) in this file")
                print(f"  ✓ Saved to: {output_file}\n")
            else:
                print(f"  → No rules with 'memonly' found - skipping output\n")
        else:
            print(f"  ✗ Failed to process {yar_file.name}\n")
    
    print(f"\nCompleted: {success_count}/{len(yar_files)} files processed successfully")
    print(f"Total rules modified: {total_rules_modified}")


if __name__ == '__main__':
    main()
