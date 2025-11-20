#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check YARA Rules Against Baseline Database

This script checks new rules against the baseline database and filters out
rules that already exist. This should be run FIRST before any validation.

Usage:
    python check_baseline.py <input_dir> --database <db_path> --output-new <new_dir>
"""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.shared_utils import (
    collect_yara_files,
    parse_yara_file_to_rules,
    extract_rule_name,
    RuleFingerprint,
    write_file_with_header
)

try:
    from build_rule_database import RuleDatabase
except ImportError:
    print("Error: Could not import RuleDatabase from build_rule_database.py", file=sys.stderr)
    sys.exit(1)


class BaselineFilter:
    """Filter rules against baseline database."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.db = None
        self.new_rules = []
        self.existing_rules = []
        self.stats = {
            'total_files': 0,
            'total_rules': 0,
            'new_rules': 0,
            'existing_rules': 0
        }
    
    def connect(self):
        """Connect to database."""
        if not os.path.exists(self.db_path):
            print(f"⚠️  Database not found: {self.db_path}")
            print(f"    All rules will be treated as NEW")
            return False
        
        self.db = RuleDatabase(self.db_path)
        self.db.connect()
        return True
    
    def check_file(self, filepath, verbose=False):
        """
        Check all rules in a file against the database.
        Returns: (new_rules, existing_rules)
        """
        if verbose:
            print(f"\n📄 Checking: {os.path.basename(filepath)}")
        
        imports, rule_sources = parse_yara_file_to_rules(filepath)
        
        file_new_rules = []
        file_existing_rules = []
        
        for rule_source in rule_sources:
            self.stats['total_rules'] += 1
            
            rule_name = extract_rule_name(rule_source)
            if not rule_name:
                continue
            
            # Compute hash
            fingerprint = RuleFingerprint(rule_source)
            rule_hash = fingerprint.hash
            
            # Check if exists in database
            is_new = True
            existing_info = None
            
            if self.db:
                result = self.db.rule_exists_by_hash(rule_hash)
                if result:
                    is_new = False
                    existing_info = result
            
            if is_new:
                file_new_rules.append({
                    'name': rule_name,
                    'source': rule_source,
                    'hash': rule_hash
                })
                self.stats['new_rules'] += 1
                
                if verbose:
                    print(f"  ✅ NEW: {rule_name}")
            else:
                existing_rule_name, existing_file = existing_info
                file_existing_rules.append({
                    'name': rule_name,
                    'source': rule_source,
                    'hash': rule_hash,
                    'existing_name': existing_rule_name,
                    'existing_file': existing_file
                })
                self.stats['existing_rules'] += 1
                
                if verbose:
                    print(f"  ⏭️  EXISTS: {rule_name} (as '{existing_rule_name}' in {os.path.basename(existing_file)})")
        
        return file_new_rules, file_existing_rules, imports
    
    def process_directory(self, input_dir, output_new_dir, output_existing_dir, verbose=False):
        """Process all files in directory."""
        print("="*80)
        print("YARA Baseline Filter")
        print("="*80)
        print(f"Input Directory: {os.path.abspath(input_dir)}")
        print(f"Database: {self.db_path}")
        print("="*80)
        
        # Collect files
        yara_files = collect_yara_files(input_dir)
        
        if not yara_files:
            print(f"\n❌ No YARA files found in {input_dir}")
            return False
        
        print(f"\n📁 Found {len(yara_files)} YARA file(s)")
        self.stats['total_files'] = len(yara_files)
        
        # Connect to database
        db_connected = self.connect()
        if not db_connected:
            print("⚠️  Proceeding without database - all rules treated as NEW")
        
        print("\n🔍 Checking rules against baseline...")
        
        # Process each file
        for filepath in yara_files:
            new_rules, existing_rules, imports = self.check_file(filepath, verbose)
            
            filename = os.path.basename(filepath)
            
            # Write new rules to output directory
            if new_rules and output_new_dir:
                output_path = os.path.join(output_new_dir, filename)
                
                # Reconstruct file content
                content = ""
                if imports:
                    content += imports + "\n\n"
                content += "\n\n".join([rule['source'] for rule in new_rules])
                
                header_info = {
                    'Source': filepath,
                    'Checked': datetime.now().isoformat(),
                    'New Rules': len(new_rules),
                    'Status': 'NEW - Not in baseline'
                }
                
                write_file_with_header(output_path, content, header_info)
            
            # Write existing rules to separate directory
            if existing_rules and output_existing_dir:
                output_path = os.path.join(output_existing_dir, filename)
                
                # Reconstruct file content with notes
                content = ""
                if imports:
                    content += imports + "\n\n"
                
                for rule in existing_rules:
                    content += f"// ALREADY IN BASELINE: '{rule['existing_name']}' in {rule['existing_file']}\n"
                    content += f"// Hash: {rule['hash'][:16]}\n"
                    content += rule['source'] + "\n\n"
                
                header_info = {
                    'Source': filepath,
                    'Checked': datetime.now().isoformat(),
                    'Existing Rules': len(existing_rules),
                    'Status': 'SKIPPED - Already in baseline'
                }
                
                write_file_with_header(output_path, content, header_info)
            
            # Track for report
            for rule in new_rules:
                self.new_rules.append({
                    'rule_name': rule['name'],
                    'file': filepath,
                    'hash': rule['hash'][:16]
                })
            
            for rule in existing_rules:
                self.existing_rules.append({
                    'rule_name': rule['name'],
                    'file': filepath,
                    'hash': rule['hash'][:16],
                    'existing_name': rule['existing_name'],
                    'existing_file': rule['existing_file']
                })
        
        return True
    
    def get_report(self):
        """Generate report data."""
        return {
            'timestamp': datetime.now().isoformat(),
            'database': self.db_path,
            'statistics': self.stats,
            'new_rules': self.new_rules,
            'existing_rules': self.existing_rules
        }
    
    def close(self):
        """Close database connection."""
        if self.db:
            self.db.close()


def main():
    parser = argparse.ArgumentParser(
        description='Check YARA rules against baseline database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  
  # Check rules against database
  python %(prog)s ./new_rules --database rules.db --output-new ./truly_new --output-existing ./already_in_baseline
  
  # With verbose output
  python %(prog)s ./new_rules --database rules.db --output-new ./truly_new --verbose
        """
    )
    
    parser.add_argument('input_dir',
                       help='Directory containing new YARA rules to check')
    
    parser.add_argument('--database', '-d', required=True,
                       help='Path to baseline database')
    
    parser.add_argument('--output-new', metavar='DIR',
                       help='Output directory for NEW rules (not in baseline)')
    
    parser.add_argument('--output-existing', metavar='DIR',
                       help='Output directory for rules already in baseline')
    
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
        # Create filter
        filter = BaselineFilter(args.database)
        
        # Process directory
        success = filter.process_directory(
            args.input_dir,
            args.output_new,
            args.output_existing,
            args.verbose
        )
        
        if not success:
            sys.exit(2)
        
        # Print results
        stats = filter.stats
        print("\n" + "="*80)
        print("BASELINE CHECK RESULTS")
        print("="*80)
        print(f"Total Files:      {stats['total_files']}")
        print(f"Total Rules:      {stats['total_rules']}")
        print(f"✅ NEW Rules:     {stats['new_rules']}")
        print(f"⏭️  EXISTING:      {stats['existing_rules']}")
        print("="*80)
        
        # Generate JSON report
        if args.json_report:
            report = filter.get_report()
            os.makedirs(os.path.dirname(args.json_report), exist_ok=True)
            with open(args.json_report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📝 Report saved: {args.json_report}")
        
        # Close database
        filter.close()
        
        # Exit code based on results
        if stats['new_rules'] == 0:
            print("\nℹ️  No new rules found - all rules already in baseline")
            sys.exit(0)
        else:
            print(f"\n✅ Found {stats['new_rules']} new rule(s) to process")
            sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
