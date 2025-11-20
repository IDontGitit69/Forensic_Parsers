#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared utilities for YARA rule processing scripts
"""

import os
import sys
import glob
import re
import hashlib
from datetime import datetime
from pathlib import Path


# ============================================================================
# RULE FINGERPRINTING
# ============================================================================

class RuleFingerprint:
    """Computes and stores a hash fingerprint of a YARA rule's content."""
    
    def __init__(self, rule_source):
        self.rule_source = rule_source
        self.hash = self._compute_hash()
    
    def _compute_hash(self):
        '''
        Compute SHA256 hash of rule content (strings + condition sections only).
        This excludes metadata and rule name to detect content duplicates.
        '''
        # Extract strings and condition sections
        content_parts = []
        
        # Extract strings section
        strings_match = re.search(r'strings:\s*(.*?)(?:condition:|$)', 
                                 self.rule_source, re.DOTALL | re.IGNORECASE)
        if strings_match:
            content_parts.append(strings_match.group(1).strip())
        
        # Extract condition section
        condition_match = re.search(r'condition:\s*(.*?)(?:\}|$)', 
                                   self.rule_source, re.DOTALL | re.IGNORECASE)
        if condition_match:
            content_parts.append(condition_match.group(1).strip())
        
        # Combine and normalize
        combined = '\n'.join(content_parts)
        normalized = re.sub(r'\s+', ' ', combined.strip())
        
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    
    def __eq__(self, other):
        return isinstance(other, RuleFingerprint) and self.hash == other.hash
    
    def __hash__(self):
        return hash(self.hash)
    
    def __str__(self):
        return self.hash[:16]


# ============================================================================
# FILE OPERATIONS
# ============================================================================

def collect_yara_files(directory, extensions=None):
    """Collect all YARA rule files from a directory."""
    if extensions is None:
        extensions = ['.yar', '.yara', '.rule']
    
    yara_files = []
    for ext in extensions:
        pattern = os.path.join(directory, '**', f'*{ext}')
        yara_files.extend(glob.glob(pattern, recursive=True))
    
    return sorted(set(yara_files))


def parse_yara_file_to_rules(filepath):
    """
    Parse a YARA file and extract individual rules with their imports.
    Returns: tuple: (imports_string, list_of_rule_sources)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        return "", []
    
    rule_pattern = re.compile(r'(?i)^\s*(private\s+|global\s+)?rule\s+\w+')
    
    header_lines = []
    rule_blocks = []
    current_rule = []
    in_rule = False
    
    for line in lines:
        if rule_pattern.match(line):
            if current_rule:
                rule_blocks.append(current_rule)
            current_rule = [line]
            in_rule = True
        else:
            if not in_rule:
                header_lines.append(line)
            else:
                current_rule.append(line)
    
    if current_rule:
        rule_blocks.append(current_rule)
    
    import_lines = []
    for line in header_lines:
        if re.match(r'^\s*import\s+"[^"]+"\s*$', line):
            import_lines.append(line.rstrip())
    
    imports_string = '\n'.join(import_lines) if import_lines else ""
    
    rules = []
    for rule_block in rule_blocks:
        rule_text = ''.join(rule_block).strip()
        if rule_text:
            rules.append(rule_text)
    
    return imports_string, rules


def extract_rule_name(rule_source):
    """Extract the rule name from YARA rule source."""
    match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', 
                     rule_source, re.MULTILINE)
    return match.group(1) if match else None


def write_file_with_header(filepath, content, header_info):
    """Write a file with a standardized header."""
    header = ""
    for key, value in header_info.items():
        header += f"// {key}: {value}\n"
    header += "\n"
    
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing {filepath}: {e}", file=sys.stderr)
        return False
