#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Rule Database Helper Module

Provides database access for checking rules against the baseline.
"""

import sqlite3
import os


class RuleDatabaseChecker:
    """Helper class to check rules against the baseline database."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._connected = False
    
    def connect(self):
        """Connect to the database."""
        if not os.path.exists(self.db_path):
            # Database doesn't exist - this is okay, we'll just skip checks
            return False
        
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            self._connected = True
            return True
        except Exception as e:
            print(f"⚠️  Warning: Could not connect to database: {e}")
            return False
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self._connected = False
    
    def is_connected(self):
        """Check if database is connected."""
        return self._connected
    
    def rule_exists_by_hash(self, rule_hash):
        """
        Check if a rule with this hash exists in baseline.
        Returns: (rule_name, file_path) or None
        """
        if not self._connected:
            return None
        
        try:
            self.cursor.execute("""
                SELECT r.rule_name, f.file_path
                FROM rules r
                JOIN files f ON r.file_id = f.id
                WHERE r.rule_hash = ?
                LIMIT 1
            """, (rule_hash,))
            return self.cursor.fetchone()
        except Exception as e:
            print(f"⚠️  Database query error: {e}")
            return None
    
    def rule_exists_by_name(self, rule_name):
        """
        Check if a rule with this name exists in baseline.
        Returns: list of (file_path, rule_hash)
        """
        if not self._connected:
            return []
        
        try:
            self.cursor.execute("""
                SELECT f.file_path, r.rule_hash
                FROM rules r
                JOIN files f ON r.file_id = f.id
                WHERE r.rule_name = ?
            """, (rule_name,))
            return self.cursor.fetchall()
        except Exception as e:
            print(f"⚠️  Database query error: {e}")
            return []
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
