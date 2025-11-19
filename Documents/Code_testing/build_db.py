#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Rule Database Builder

Creates and maintains a SQLite database of YARA rules in the baseline directory.
Uses content-based hashing (strings + condition sections only) to detect duplicates.

Usage:
    python build_rule_database.py <baseline_directory> --database rules.db
    
    # Rebuild database from scratch
    python build_rule_database.py <baseline_directory> --database rules.db --rebuild
    
    # Query database
    python build_rule_database.py --database rules.db --query-rule "rule_name"
    python build_rule_database.py --database rules.db --query-hash "abc123..."
    python build_rule_database.py --database rules.db --stats
"""

import argparse
import os
import sys
import sqlite3
import hashlib
import re
from datetime import datetime
from pathlib import Path

# Import necessary components from the validation script
try:
    from validate_yara_rules import (
        RuleFingerprint,
        collect_yara_files,
        parse_yara_file_to_rules
    )
except ImportError:
    print("Error: Could not import from validate_yara_rules.py", file=sys.stderr)
    print("Make sure validate_yara_rules.py is in the same directory", file=sys.stderr)
    sys.exit(1)


class RuleDatabase:
    """SQLite database for YARA rules with content-based hashing."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def connect(self):
        """Connect to the database."""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA foreign_keys = ON")
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
    
    def create_schema(self):
        """Create database schema."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                last_modified DATETIME
            )
        """)
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                rule_hash TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for faster lookups
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rule_name ON rules(rule_name)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rule_hash ON rules(rule_hash)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_path ON files(file_path)
        """)
        
        self.conn.commit()
        print("✅ Database schema created successfully")
    
    def drop_schema(self):
        """Drop all tables (for rebuild)."""
        self.cursor.execute("DROP TABLE IF EXISTS rules")
        self.cursor.execute("DROP TABLE IF EXISTS files")
        self.conn.commit()
        print("🗑️  Dropped existing tables")
    
    def add_or_update_file(self, file_path):
        """Add or update a file in the database. Returns file_id."""
        abs_path = os.path.abspath(file_path)
        last_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
        
        # Check if file exists
        self.cursor.execute(
            "SELECT id, last_modified FROM files WHERE file_path = ?",
            (abs_path,)
        )
        result = self.cursor.fetchone()
        
        if result:
            file_id, db_last_modified = result
            # Update last_modified if changed
            if db_last_modified != last_modified.isoformat():
                self.cursor.execute(
                    "UPDATE files SET last_modified = ? WHERE id = ?",
                    (last_modified, file_id)
                )
                print(f"  📝 Updated: {os.path.basename(file_path)}")
            return file_id
        else:
            # Insert new file
            self.cursor.execute(
                "INSERT INTO files (file_path, last_modified) VALUES (?, ?)",
                (abs_path, last_modified)
            )
            file_id = self.cursor.lastrowid
            print(f"  ➕ Added: {os.path.basename(file_path)}")
            return file_id
    
    def add_rule(self, file_id, rule_name, rule_hash):
        """Add a rule to the database."""
        self.cursor.execute(
            "INSERT INTO rules (file_id, rule_name, rule_hash) VALUES (?, ?, ?)",
            (file_id, rule_name, rule_hash)
        )
    
    def delete_rules_for_file(self, file_id):
        """Delete all rules associated with a file."""
        self.cursor.execute("DELETE FROM rules WHERE file_id = ?", (file_id,))
    
    def rule_exists_by_hash(self, rule_hash):
        """Check if a rule with this hash exists. Returns (rule_name, file_path) or None."""
        self.cursor.execute("""
            SELECT r.rule_name, f.file_path
            FROM rules r
            JOIN files f ON r.file_id = f.id
            WHERE r.rule_hash = ?
            LIMIT 1
        """, (rule_hash,))
        return self.cursor.fetchone()
    
    def rule_exists_by_name(self, rule_name):
        """Check if a rule with this name exists. Returns list of (file_path, rule_hash)."""
        self.cursor.execute("""
            SELECT f.file_path, r.rule_hash
            FROM rules r
            JOIN files f ON r.file_id = f.id
            WHERE r.rule_name = ?
        """, (rule_name,))
        return self.cursor.fetchall()
    
    def get_all_rules(self):
        """Get all rules in the database."""
        self.cursor.execute("""
            SELECT r.rule_name, r.rule_hash, f.file_path, f.last_modified
            FROM rules r
            JOIN files f ON r.file_id = f.id
            ORDER BY f.file_path, r.rule_name
        """)
        return self.cursor.fetchall()
    
    def get_statistics(self):
        """Get database statistics."""
        self.cursor.execute("SELECT COUNT(*) FROM files")
        file_count = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM rules")
        rule_count = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(DISTINCT rule_hash) FROM rules")
        unique_hashes = self.cursor.fetchone()[0]
        
        self.cursor.execute("""
            SELECT rule_hash, COUNT(*) as count
            FROM rules
            GROUP BY rule_hash
            HAVING count > 1
        """)
        duplicate_hashes = self.cursor.fetchall()
        
        return {
            'total_files': file_count,
            'total_rules': rule_count,
            'unique_hashes': unique_hashes,
            'duplicate_hashes': len(duplicate_hashes),
            'duplicates': duplicate_hashes
        }


def build_database(baseline_dir, db_path, rebuild=False, verbose=False):
    """Build or update the rule database from baseline directory."""
    
    print("="*80)
    print("YARA Rule Database Builder")
    print("="*80)
    print(f"Baseline Directory: {os.path.abspath(baseline_dir)}")
    print(f"Database: {db_path}")
    if rebuild:
        print("Mode: REBUILD (clearing existing data)")
    else:
        print("Mode: UPDATE (incremental)")
    print("="*80)
    
    # Collect YARA files
    print("\n📁 Scanning for YARA files...")
    yara_files = collect_yara_files(baseline_dir)
    
    if not yara_files:
        print(f"❌ No YARA files found in {baseline_dir}")
        return False
    
    print(f"✅ Found {len(yara_files)} YARA file(s)")
    
    # Connect to database
    db = RuleDatabase(db_path)
    db.connect()
    
    try:
        if rebuild:
            db.drop_schema()
        
        db.create_schema()
        
        # Process each file
        print("\n📊 Processing files...")
        total_rules_added = 0
        total_files_processed = 0
        
        for filepath in yara_files:
            if verbose:
                print(f"\n📄 Processing: {os.path.basename(filepath)}")
            
            try:
                # Add or update file record
                file_id = db.add_or_update_file(filepath)
                
                # Delete existing rules for this file (for update mode)
                if not rebuild:
                    db.delete_rules_for_file(file_id)
                
                # Parse rules from file
                imports, rule_sources = parse_yara_file_to_rules(filepath)
                
                # Process each rule
                for rule_source in rule_sources:
                    # Extract rule name
                    rule_name_match = re.search(
                        r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)',
                        rule_source,
                        re.MULTILINE
                    )
                    
                    if not rule_name_match:
                        print(f"  ⚠️  Could not extract rule name from rule in {filepath}")
                        continue
                    
                    rule_name = rule_name_match.group(1)
                    
                    # Compute content hash using RuleFingerprint
                    fingerprint = RuleFingerprint(rule_source)
                    rule_hash = fingerprint.hash
                    
                    # Add rule to database
                    db.add_rule(file_id, rule_name, rule_hash)
                    total_rules_added += 1
                    
                    if verbose:
                        print(f"    ✓ {rule_name} [{rule_hash[:16]}]")
                
                total_files_processed += 1
                
            except Exception as e:
                print(f"  ❌ Error processing {filepath}: {e}")
                continue
        
        # Commit changes
        db.conn.commit()
        
        # Show statistics
        print("\n" + "="*80)
        print("DATABASE STATISTICS")
        print("="*80)
        stats = db.get_statistics()
        print(f"Total Files:        {stats['total_files']}")
        print(f"Total Rules:        {stats['total_rules']}")
        print(f"Unique Hashes:      {stats['unique_hashes']}")
        
        if stats['duplicate_hashes'] > 0:
            print(f"⚠️  Duplicate Hashes: {stats['duplicate_hashes']}")
            if verbose:
                print("\nDuplicate content detected:")
                for rule_hash, count in stats['duplicates']:
                    print(f"  Hash {rule_hash[:16]}... appears {count} times")
        
        print("="*80)
        print(f"\n✅ Database built successfully!")
        print(f"📁 Database location: {os.path.abspath(db_path)}")
        print(f"📊 Processed {total_files_processed} files, {total_rules_added} rules")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error building database: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


def query_database(db_path, rule_name=None, rule_hash=None, show_stats=False):
    """Query the database for rules."""
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    db = RuleDatabase(db_path)
    db.connect()
    
    try:
        if show_stats:
            print("="*80)
            print("DATABASE STATISTICS")
            print("="*80)
            stats = db.get_statistics()
            print(f"Total Files:        {stats['total_files']}")
            print(f"Total Rules:        {stats['total_rules']}")
            print(f"Unique Hashes:      {stats['unique_hashes']}")
            
            if stats['duplicate_hashes'] > 0:
                print(f"⚠️  Duplicate Hashes: {stats['duplicate_hashes']}")
                print("\nDuplicate content detected:")
                for rule_hash, count in stats['duplicates']:
                    print(f"  Hash {rule_hash[:16]}... appears {count} times")
            print("="*80)
        
        elif rule_name:
            print(f"\n🔍 Searching for rule name: '{rule_name}'")
            results = db.rule_exists_by_name(rule_name)
            
            if results:
                print(f"✅ Found {len(results)} occurrence(s):")
                for file_path, hash_val in results:
                    print(f"  📄 {file_path}")
                    print(f"     Hash: {hash_val[:16]}...")
            else:
                print(f"❌ Rule '{rule_name}' not found in database")
        
        elif rule_hash:
            print(f"\n🔍 Searching for hash: {rule_hash[:16]}...")
            result = db.rule_exists_by_hash(rule_hash)
            
            if result:
                rule_name, file_path = result
                print(f"✅ Found matching rule:")
                print(f"  Rule Name: {rule_name}")
                print(f"  File: {file_path}")
            else:
                print(f"❌ Hash not found in database")
        
        else:
            # Show all rules
            print("\n📋 All rules in database:")
            rules = db.get_all_rules()
            
            current_file = None
            for rule_name, rule_hash, file_path, last_modified in rules:
                if file_path != current_file:
                    current_file = file_path
                    print(f"\n📄 {file_path}")
                    print(f"   Modified: {last_modified}")
                print(f"   • {rule_name} [{rule_hash[:16]}...]")
        
        return True
        
    except Exception as e:
        print(f"❌ Error querying database: {e}")
        return False
    finally:
        db.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='YARA Rule Database Builder and Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

  # Build database from baseline directory
  python %(prog)s /path/to/baseline --database rules.db
  
  # Rebuild database from scratch
  python %(prog)s /path/to/baseline --database rules.db --rebuild
  
  # Show database statistics
  python %(prog)s --database rules.db --stats
  
  # Query by rule name
  python %(prog)s --database rules.db --query-rule "APT_Malware_Detection"
  
  # Query by hash
  python %(prog)s --database rules.db --query-hash "a3f5d8c9e2b1..."
  
  # List all rules
  python %(prog)s --database rules.db --list-all
        """
    )
    
    parser.add_argument('baseline_directory', nargs='?',
                       help='Directory containing baseline YARA rules')
    
    parser.add_argument('--database', '-d', required=True,
                       help='Path to SQLite database file')
    
    parser.add_argument('--rebuild', action='store_true',
                       help='Rebuild database from scratch (deletes existing data)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    # Query options
    parser.add_argument('--stats', action='store_true',
                       help='Show database statistics')
    
    parser.add_argument('--query-rule', metavar='NAME',
                       help='Query database by rule name')
    
    parser.add_argument('--query-hash', metavar='HASH',
                       help='Query database by rule hash')
    
    parser.add_argument('--list-all', action='store_true',
                       help='List all rules in database')
    
    args = parser.parse_args()
    
    # Determine mode: build or query
    is_query_mode = any([args.stats, args.query_rule, args.query_hash, args.list_all])
    
    if is_query_mode:
        # Query mode
        success = query_database(
            args.database,
            rule_name=args.query_rule,
            rule_hash=args.query_hash,
            show_stats=args.stats or args.list_all
        )
        sys.exit(0 if success else 1)
    else:
        # Build mode
        if not args.baseline_directory:
            parser.error("baseline_directory is required for building the database")
        
        if not os.path.isdir(args.baseline_directory):
            print(f"❌ Error: Directory not found: {args.baseline_directory}")
            sys.exit(1)
        
        success = build_database(
            args.baseline_directory,
            args.database,
            rebuild=args.rebuild,
            verbose=args.verbose
        )
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
