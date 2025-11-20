#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Rule Database Updater

Adds validated YARA rules to the baseline database.
Skips rules that already exist (by content hash).

Usage:
    python update_database.py <rules_dir> --database <db_path>
"""

import argparse
import os
import sys
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.shared_utils import (
    collect_yara_files,
    parse_yara_file_to_rules,
    extract_rule_name,
    RuleFingerprint
)

try:
    from build_rule_database import RuleDatabase
except ImportError:
    print("Error: Could not import from build_rule_database.py", file=sys.stderr)
    sys.exit(1)


class DatabaseUpdater:
    """Updates YARA rules database."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.db = RuleDatabase(db_path)
        self.rules_added = 0
        self.rules_skipped = 0
        self.add_log = []
        self.skip_log = []
    
    def connect(self):
        """Connect to database and ensure schema exists."""
        self.db.connect()
        self.db.create_schema()
    
    def add_rules_from_file(self, file_path, verbose=False):
        """
        Add all rules from a YARA file to the database.
        Returns: (added_count, skipped_count)
        """
        if verbose:
            print(f"\n📄 Processing: {os.path.basename(file_path)}")
        
        try:
            imports, rule_sources = parse_yara_file_to_rules(file_path)
            
            added = 0
            skipped = 0
            
            for rule_source in rule_sources:
                rule_name = extract_rule_name(rule_source)
                if not rule_name:
                    continue
                
                # Compute hash
                fingerprint = RuleFingerprint(rule_source)
                rule_hash = fingerprint.hash
                
                # Check if exists
                existing = self.db.rule_exists_by_hash(rule_hash)
                
                if existing:
                    # Rule already exists
                    skipped += 1
                    self.rules_skipped += 1
                    existing_rule_name, existing_file = existing
                    
                    self.skip_log.append({
                        'rule_name': rule_name,
                        'file': file_path,
                        'existing_rule': existing_rule_name,
                        'existing_file': existing_file,
                        'hash': rule_hash[:16]
                    })
                    
                    if verbose:
                        print(f"  ⏭️  Skipped: {rule_name} (already exists as '{existing_rule_name}')")
                else:
                    # Add new rule
                    file_id = self.db.add_or_update_file(file_path)
                    self.db.add_rule(file_id, rule_name, rule_hash)
                    
                    added += 1
                    self.rules_added += 1
                    
                    self.add_log.append({
                        'rule_name': rule_name,
                        'file': file_path,
                        'hash': rule_hash[:16]
                    })
                    
                    if verbose:
                        print(f"  ✅ Added: {rule_name}")
            
            # Commit after each file
            self.db.conn.commit()
            
            return added, skipped
            
        except Exception as e:
            print(f"  ⚠️  Error processing {file_path}: {e}")
            return 0, 0
    
    def process_directory(self, input_dir, verbose=False):
        """Process all files in directory."""
        print("="*80)
        print("YARA Database Updater")
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
        print("\n💾 Updating database...")
        
        # Process each file
        for filepath in yara_files:
            self.add_rules_from_file(filepath, verbose)
        
        return True
    
    def get_report(self):
        """Generate report data."""
        return {
            'timestamp': datetime.now().isoformat(),
            'database': self.db_path,
            'statistics': {
                'total_added': self.rules_added,
                'total_skipped': self.rules_skipped
            },
            'added_rules': self.add_log,
            'skipped_rules': self.skip_log
        }
    
    def close(self):
        """Close database connection."""
        self.db.close()


def main():
    parser = argparse.ArgumentParser(
        description='Update YARA rules database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  
  # Update database with validated rules
  python %(prog)s ./validated_rules --database rules.db
  
  # With JSON report
  python %(prog)s ./validated_rules --database rules.db --json-report db_update.json
  
  # Verbose mode
  python %(prog)s ./validated_rules --database rules.db --verbose
        """
    )
    
    parser.add_argument('input_dir',
                       help='Directory containing validated YARA rules to add')
    
    parser.add_argument('--database', '-d', required=True,
                       help='Path to SQLite database file')
    
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
        # Create updater
        updater = DatabaseUpdater(args.database)
        updater.connect()
        
        # Process directory
        success = updater.process_directory(args.input_dir, args.verbose)
        
        if not success:
            updater.close()
            sys.exit(2)
        
        # Print results
        print("\n" + "="*80)
        print("DATABASE UPDATE RESULTS")
        print("="*80)
        print(f"✅ Rules Added:    {updater.rules_added}")
        print(f"⏭️  Rules Skipped:  {updater.rules_skipped}")
        print("="*80)
        
        # Generate JSON report
        if args.json_report:
            report = updater.get_report()
            os.makedirs(os.path.dirname(args.json_report), exist_ok=True)
            with open(args.json_report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📝 Report saved: {args.json_report}")
        
        # Close database
        updater.close()
        
        print(f"\n✅ Database updated successfully!")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
