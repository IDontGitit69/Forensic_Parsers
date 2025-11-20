#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Rule Deduplicator

Detects and handles duplicate YARA rules using content-based hashing.
Can remove content duplicates and rename name conflicts.

Usage:
    python deduplicate_rules.py <input_dir> --output-dir <clean_dir>
"""

import argparse
import os
import sys
import json
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.shared_utils import (
    collect_yara_files,
    parse_yara_file_to_rules,
    extract_rule_name,
    RuleFingerprint,
    write_file_with_header
)


class DuplicateInfo:
    """Tracks information about duplicate rules."""
    
    TYPE_NAME_CONFLICT = 'name_conflict'
    TYPE_CONTENT_DUPLICATE = 'content_duplicate'
    
    def __init__(self, rule_name, duplicate_type, original_file, original_hash, original_name=None):
        self.rule_name = rule_name
        self.duplicate_type = duplicate_type
        self.original_file = original_file
        self.original_hash = original_hash
        self.original_name = original_name
    
    def to_dict(self):
        result = {
            'rule_name': self.rule_name,
            'type': self.duplicate_type,
            'original_file': self.original_file,
            'original_hash': self.original_hash[:16]
        }
        if self.original_name:
            result['original_name'] = self.original_name
        return result


class DeduplicationTracker:
    """Tracks all deduplication actions."""
    
    def __init__(self):
        self.rule_registry = {}  # rule_name -> {hash, file, content}
        self.hash_registry = {}  # hash -> [rule_names]
        self.duplicates = []
        self.renames = []
        self.removals = []
    
    def register_rule(self, rule_name, rule_content, file_path):
        '''
        Register a rule and check for duplicates.
        Returns: (should_keep, new_name_if_renamed, duplicate_info)
        '''
        fingerprint = RuleFingerprint(rule_content)
        rule_hash = fingerprint.hash
        
        # Check for content duplicates (same hash, any name)
        if rule_hash in self.hash_registry:
            existing_names = self.hash_registry[rule_hash]
            if existing_names:
                original_name = existing_names[0]
                original_rule = self.rule_registry[original_name]
                
                # Content duplicate - remove regardless of name match
                duplicate_info = DuplicateInfo(
                    rule_name, 
                    DuplicateInfo.TYPE_CONTENT_DUPLICATE,
                    original_rule['file'],
                    original_rule['hash'],
                    original_name=original_name
                )
                self.duplicates.append(duplicate_info)
                self.removals.append({
                    'rule_name': rule_name,
                    'file': file_path,
                    'reason': f'Content duplicate - identical to "{original_name}" in {original_rule["file"]}',
                    'hash': rule_hash[:16],
                    'original_name': original_name,
                    'duplicate_type': 'content_duplicate'
                })
                return False, None, duplicate_info
        
        # Check for name conflicts (different content, same name)
        if rule_name in self.rule_registry:
            existing = self.rule_registry[rule_name]
            # Only rename if content is actually different
            if existing['hash'] != rule_hash:
                new_name = self._find_unique_name(rule_name)
                duplicate_info = DuplicateInfo(
                    rule_name,
                    DuplicateInfo.TYPE_NAME_CONFLICT,
                    existing['file'],
                    existing['hash']
                )
                self.duplicates.append(duplicate_info)
                self.renames.append({
                    'original_name': rule_name,
                    'new_name': new_name,
                    'file': file_path,
                    'reason': f'Name conflict - different rule with same name exists in {existing["file"]}',
                    'original_hash': existing['hash'][:16],
                    'new_hash': rule_hash[:16],
                    'duplicate_type': 'name_conflict'
                })
                
                # Register with new name
                self.rule_registry[new_name] = {
                    'hash': rule_hash,
                    'file': file_path,
                    'content': rule_content
                }
                
                if rule_hash not in self.hash_registry:
                    self.hash_registry[rule_hash] = []
                self.hash_registry[rule_hash].append(new_name)
                
                return True, new_name, duplicate_info
        
        # New unique rule
        self.rule_registry[rule_name] = {
            'hash': rule_hash,
            'file': file_path,
            'content': rule_content
        }
        
        if rule_hash not in self.hash_registry:
            self.hash_registry[rule_hash] = []
        self.hash_registry[rule_hash].append(rule_name)
        
        return True, None, None
    
    def _find_unique_name(self, base_name):
        """Find a unique name by appending _1, _2, etc."""
        counter = 1
        while f"{base_name}_{counter}" in self.rule_registry:
            counter += 1
        return f"{base_name}_{counter}"
    
    def get_statistics(self):
        '''Get deduplication statistics.'''
        name_conflicts = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_NAME_CONFLICT)
        content_duplicates = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_CONTENT_DUPLICATE)
        
        return {
            'total_duplicates': len(self.duplicates),
            'name_conflicts': name_conflicts,
            'content_duplicates': content_duplicates,
            'renames': len(self.renames),
            'removals': len(self.removals)
        }
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'statistics': self.get_statistics(),
            'duplicates': [d.to_dict() for d in self.duplicates],
            'renames': self.renames,
            'removals': self.removals
        }


class Deduplicator:
    """Deduplicates YARA rules."""
    
    def __init__(self):
        self.tracker = DeduplicationTracker()
        self.processed_files = []
    
    def deduplicate_file(self, filepath, verbose=False):
        """
        Deduplicate rules within a file.
        Returns: (kept_rules, imports, changed)
        """
        if verbose:
            print(f"\n📄 Processing: {os.path.basename(filepath)}")
        
        imports, rule_sources = parse_yara_file_to_rules(filepath)
        
        kept_rules = []
        changed = False
        
        for rule_source in rule_sources:
            rule_name = extract_rule_name(rule_source)
            if not rule_name:
                kept_rules.append(rule_source)
                continue
            
            # Register and check for duplicates
            should_keep, new_name, duplicate_info = self.tracker.register_rule(
                rule_name,
                rule_source,
                filepath
            )
            
            if not should_keep:
                changed = True
                if verbose:
                    if duplicate_info and duplicate_info.duplicate_type == DuplicateInfo.TYPE_CONTENT_DUPLICATE:
                        print(f"  🗑️  Removing: '{rule_name}' (duplicate of '{duplicate_info.original_name}')")
                    else:
                        print(f"  🗑️  Removing: '{rule_name}'")
                continue
            
            elif new_name:
                changed = True
                if verbose:
                    print(f"  🔄 Renaming: '{rule_name}' → '{new_name}'")
                
                # Rename the rule in source
                renamed_source = re.sub(
                    r'(?i)(^\s*(?:private\s+|global\s+)?rule\s+)(\w+)',
                    r'\g<1>' + new_name,
                    rule_source,
                    count=1,
                    flags=re.MULTILINE
                )
                kept_rules.append(renamed_source)
            else:
                if verbose:
                    print(f"  ✅ Keeping: '{rule_name}'")
                kept_rules.append(rule_source)
        
        return kept_rules, imports, changed
    
    def process_directory(self, input_dir, output_dir, verbose=False):
        """Process all files in directory."""
        print("="*80)
        print("YARA Rule Deduplicator")
        print("="*80)
        print(f"Input Directory: {os.path.abspath(input_dir)}")
        print(f"Output Directory: {os.path.abspath(output_dir)}")
        print("="*80)
        
        # Collect files
        yara_files = collect_yara_files(input_dir)
        
        if not yara_files:
            print(f"\n❌ No YARA files found in {input_dir}")
            return False
        
        print(f"\n📁 Found {len(yara_files)} YARA file(s)")
        print("\n🔍 Checking for duplicates...")
        
        # Process each file
        for filepath in yara_files:
            kept_rules, imports, changed = self.deduplicate_file(filepath, verbose)
            
            filename = os.path.basename(filepath)
            
            # Only write if there are rules left
            if kept_rules:
                output_path = os.path.join(output_dir, filename)
                
                # Reconstruct file content
                content = ""
                if imports:
                    content += imports + "\n\n"
                content += "\n\n".join(kept_rules)
                
                header_info = {
                    'Source': filepath,
                    'Processed': datetime.now().isoformat(),
                    'Rules': len(kept_rules),
                    'Status': 'Deduplicated' if changed else 'No duplicates found'
                }
                
                write_file_with_header(output_path, content, header_info)
                
                self.processed_files.append({
                    'filepath': filepath,
                    'filename': filename,
                    'rule_count': len(kept_rules),
                    'was_changed': changed
                })
            else:
                if verbose:
                    print(f"  ⚠️  File empty after deduplication: {filename}")
        
        return True
    
    def get_report(self):
        """Generate report data."""
        return {
            'timestamp': datetime.now().isoformat(),
            'deduplication': self.tracker.to_dict(),
            'processed_files': self.processed_files
        }


def main():
    parser = argparse.ArgumentParser(
        description='Deduplicate YARA rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  
  # Deduplicate rules
  python %(prog)s ./rules --output-dir ./deduplicated
  
  # With JSON report
  python %(prog)s ./rules --output-dir ./deduplicated --json-report dedup_report.json
  
  # Verbose mode
  python %(prog)s ./rules --output-dir ./deduplicated --verbose
        """
    )
    
    parser.add_argument('input_dir',
                       help='Directory containing YARA rules to deduplicate')
    
    parser.add_argument('--output-dir', metavar='DIR', required=True,
                       help='Output directory for deduplicated rules')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not os.path.isdir(args.input_dir):
        print(f"❌ Error: Input directory not found: {args.input_dir}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Create deduplicator
        deduplicator = Deduplicator()
        
        # Process directory
        success = deduplicator.process_directory(
            args.input_dir,
            args.output_dir,
            args.verbose
        )
        
        if not success:
            sys.exit(2)
        
        # Print results
        stats = deduplicator.tracker.get_statistics()
        print("\n" + "="*80)
        print("DEDUPLICATION RESULTS")
        print("="*80)
        print(f"Total Duplicates:     {stats['total_duplicates']}")
        print(f"🔄 Rules Renamed:     {stats['renames']}")
        print(f"🗑️  Rules Removed:     {stats['removals']}")
        print(f"📋 Content Duplicates: {stats['content_duplicates']}")
        print(f"⚠️  Name Conflicts:    {stats['name_conflicts']}")
        print("="*80)
        
        # Generate JSON report
        if args.json_report:
            report = deduplicator.get_report()
            os.makedirs(os.path.dirname(args.json_report), exist_ok=True)
            with open(args.json_report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📝 Report saved: {args.json_report}")
        
        # Exit code
        if stats['total_duplicates'] > 0:
            print(f"\n✅ Deduplication complete: {stats['renames']} renamed, {stats['removals']} removed")
        else:
            print(f"\n✅ No duplicates found")
        
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
