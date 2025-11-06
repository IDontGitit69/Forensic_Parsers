#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
YARA Rule Validator for CI/CD Pipelines

This script validates YARA rule files with two operation modes:

1. FILE MODE (Default): Validates entire files as-is, preserving all rules, imports, 
   and dependencies together. This is the recommended mode for most use cases.

2. SPLIT MODE (--split-rules): Parses individual rules from files and validates each 
   separately. Useful for isolating issues in multi-rule files.

NEW: Advanced Duplicate Handling:
- Detects duplicate rule names (same name, different content)
- Detects duplicate rule content (identical rules)
- Can auto-deduplicate with --deduplicate flag
- Renames conflicting rules or removes true duplicates
- Provides detailed reports of all changes

Usage:
    # Validate entire files (recommended)
    python validate_yara_rules.py <directory> --output-valid-dir validated/
    
    # Detect and report duplicates
    python validate_yara_rules.py <directory> --check-duplicates
    
    # Auto-deduplicate rules
    python validate_yara_rules.py <directory> --deduplicate --output-valid-dir deduped/

Examples:
    # File mode: Validate complete files
    python validate_yara_rules.py ./rules --output-valid-dir validated/
    
    # Check for duplicates without fixing
    python validate_yara_rules.py ./rules --check-duplicates --json-report report.json
    
    # Auto-deduplicate and fix
    python validate_yara_rules.py ./rules --deduplicate --output-valid-dir deduped/
    
    # Split mode with deduplication
    python validate_yara_rules.py ./rules --split-rules --deduplicate --output-valid-dir deduped/
"""

import argparse
import os
import sys
import glob
import shutil
import re
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed. Install it with: pip install yara-python", file=sys.stderr)
    sys.exit(1)


# ============================================================================
# RULE FINGERPRINTING AND DEDUPLICATION
# ============================================================================

class RuleFingerprint:
    """Computes and stores a hash fingerprint of a YARA rule's content."""
    
    def __init__(self, rule_source):
        self.rule_source = rule_source
        self.hash = self._compute_hash()
    
    def _compute_hash(self):
        """Compute SHA256 hash of normalized rule content."""
        # Normalize: remove leading/trailing whitespace, collapse multiple spaces
        normalized = re.sub(r'\s+', ' ', self.rule_source.strip())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    
    def __eq__(self, other):
        return isinstance(other, RuleFingerprint) and self.hash == other.hash
    
    def __hash__(self):
        return hash(self.hash)
    
    def __str__(self):
        return self.hash[:16]  # Short hash for display


class DuplicateInfo:
    """Tracks information about duplicate rules."""
    
    TYPE_NAME_CONFLICT = 'name_conflict'  # Same name, different content
    TYPE_TRUE_DUPLICATE = 'true_duplicate'  # Same name AND content
    
    def __init__(self, rule_name, duplicate_type, original_file, original_hash):
        self.rule_name = rule_name
        self.duplicate_type = duplicate_type
        self.original_file = original_file
        self.original_hash = original_hash
        self.occurrences = []  # List of (file, hash, renamed_to) tuples
    
    def add_occurrence(self, file_path, rule_hash, renamed_to=None):
        """Add an occurrence of this duplicate."""
        self.occurrences.append({
            'file': file_path,
            'hash': rule_hash,
            'renamed_to': renamed_to,
            'action': 'renamed' if renamed_to else 'removed'
        })
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'rule_name': self.rule_name,
            'type': self.duplicate_type,
            'original_file': self.original_file,
            'original_hash': self.original_hash[:16],
            'occurrences': self.occurrences
        }


class DeduplicationTracker:
    """Tracks all deduplication actions across the entire validation."""
    
    def __init__(self):
        self.rule_registry = {}  # {rule_name: {'hash': hash, 'file': file, 'content': content}}
        self.hash_registry = {}  # {hash: [rule_names]} - track which rules have this hash
        self.duplicates = []  # List of DuplicateInfo objects
        self.renames = []  # List of rename actions
        self.removals = []  # List of removal actions
        self.intra_file_dupes = defaultdict(list)  # Track duplicates within same file
    
    def register_rule(self, rule_name, rule_content, file_path):
        """
        Register a rule and check for duplicates.
        Returns: (should_keep, new_name_if_renamed, duplicate_info)
        """
        fingerprint = RuleFingerprint(rule_content)
        rule_hash = fingerprint.hash
        
        # Check if this rule name already exists
        if rule_name in self.rule_registry:
            existing = self.rule_registry[rule_name]
            
            # Compare hashes
            if existing['hash'] == rule_hash:
                # TRUE DUPLICATE: Same name and content - skip it
                duplicate_info = DuplicateInfo(
                    rule_name, 
                    DuplicateInfo.TYPE_TRUE_DUPLICATE,
                    existing['file'],
                    existing['hash']
                )
                duplicate_info.add_occurrence(file_path, rule_hash, renamed_to=None)
                self.duplicates.append(duplicate_info)
                self.removals.append({
                    'rule_name': rule_name,
                    'file': file_path,
                    'reason': 'True duplicate - identical to rule in ' + existing['file'],
                    'hash': rule_hash[:16]
                })
                return False, None, duplicate_info
            else:
                # NAME CONFLICT: Same name, different content - rename it
                new_name = self._find_unique_name(rule_name)
                duplicate_info = DuplicateInfo(
                    rule_name,
                    DuplicateInfo.TYPE_NAME_CONFLICT,
                    existing['file'],
                    existing['hash']
                )
                duplicate_info.add_occurrence(file_path, rule_hash, renamed_to=new_name)
                self.duplicates.append(duplicate_info)
                self.renames.append({
                    'original_name': rule_name,
                    'new_name': new_name,
                    'file': file_path,
                    'reason': 'Name conflict with rule in ' + existing['file'],
                    'original_hash': existing['hash'][:16],
                    'new_hash': rule_hash[:16]
                })
                
                # Register the renamed rule
                self.rule_registry[new_name] = {
                    'hash': rule_hash,
                    'file': file_path,
                    'content': rule_content
                }
                
                # Track hash
                if rule_hash not in self.hash_registry:
                    self.hash_registry[rule_hash] = []
                self.hash_registry[rule_hash].append(new_name)
                
                return True, new_name, duplicate_info
        else:
            # New rule - register it
            self.rule_registry[rule_name] = {
                'hash': rule_hash,
                'file': file_path,
                'content': rule_content
            }
            
            # Track hash
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
        """Get deduplication statistics."""
        name_conflicts = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_NAME_CONFLICT)
        true_duplicates = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_TRUE_DUPLICATE)
        
        return {
            'total_duplicates': len(self.duplicates),
            'name_conflicts': name_conflicts,
            'true_duplicates': true_duplicates,
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


# ============================================================================
# YARA FILE REPRESENTATION
# ============================================================================

class YaraFile:
    """Represents a complete YARA file with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    
    def __init__(self, filepath, content=None):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.content = content
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.rule_count = 0
    
    def load_content(self):
        """Load file content if not already loaded."""
        if self.content is None:
            try:
                with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    self.content = f.read()
            except Exception as e:
                raise IOError(f"Failed to read {self.filepath}: {e}")
        return self.content
    
    def count_rules(self):
        """Count the number of rules in the file."""
        if self.content:
            rule_pattern = re.compile(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+\w+', re.MULTILINE)
            self.rule_count = len(rule_pattern.findall(self.content))
        return self.rule_count
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'filepath': self.filepath,
            'filename': self.filename,
            'status': self.status,
            'rule_count': self.rule_count,
            'error': self.error_data
        }
    
    def __repr__(self):
        return f"<YaraFile {self.filename} - {self.status} - {self.rule_count} rules>"


class YaraRule:
    """Represents a single YARA rule with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    
    def __init__(self, source, source_file='', rule_name='', imports=''):
        self.source = source
        self.source_file = source_file
        self.rule_name = rule_name or self._extract_name()
        self.original_name = self.rule_name  # Track original name before any renaming
        self.imports = imports
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.fingerprint = RuleFingerprint(source)
        self.was_renamed = False
        self.was_removed = False
        self.duplicate_info = None
    
    def _extract_name(self):
        """Extract the rule name from source code."""
        match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', self.source, re.MULTILINE)
        return match.group(1) if match else "unknown_rule"
    
    def rename(self, new_name):
        """Rename this rule and update its source."""
        self.was_renamed = True
        self.original_name = self.rule_name
        self.rule_name = new_name
        
        # Update the source code with new name
        self.source = re.sub(
            r'(?i)(^\s*(?:private\s+|global\s+)?rule\s+)(\w+)',
            r'\g<1>' + new_name,
            self.source,
            count=1,
            flags=re.MULTILINE
        )
    
    def mark_as_duplicate(self, duplicate_info):
        """Mark this rule as a duplicate."""
        self.was_removed = True
        self.duplicate_info = duplicate_info
    
    def get_full_source(self):
        """Get complete source including imports."""
        if self.imports:
            return f"{self.imports}\n\n{self.source}"
        return self.source
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        result = {
            'source_file': self.source_file,
            'rule_name': self.rule_name,
            'status': self.status,
            'error': self.error_data,
            'hash': self.fingerprint.hash[:16]
        }
        
        if self.was_renamed:
            result['original_name'] = self.original_name
            result['renamed'] = True
        
        if self.was_removed:
            result['removed_as_duplicate'] = True
        
        return result
    
    def __repr__(self):
        suffix = ""
        if self.was_renamed:
            suffix = f" (renamed from {self.original_name})"
        elif self.was_removed:
            suffix = " (duplicate removed)"
        return f"<YaraRule {self.rule_name} - {self.status}{suffix}>"


# ============================================================================
# RULE PARSING UTILITIES
# ============================================================================

def parse_yara_file_to_rules(filepath):
    """
    Parse a YARA file and extract individual rules with their imports.
    Uses simple line-by-line approach to detect rule boundaries.
    
    Returns:
        tuple: (imports_string, list_of_rule_sources)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        return "", []
    
    # Pattern to detect start of YARA rules (case-insensitive)
    rule_pattern = re.compile(r'(?i)^\s*(private\s+|global\s+)?rule\s+\w+')
    
    # Separate header (imports/comments) from rules
    header_lines = []
    rule_blocks = []
    current_rule = []
    in_rule = False
    
    for line in lines:
        # Check if this line starts a new rule
        if rule_pattern.match(line):
            # If we were building a rule, save it
            if current_rule:
                rule_blocks.append(current_rule)
            # Start a new rule
            current_rule = [line]
            in_rule = True
        else:
            # If we're not in a rule yet, this is part of the header
            if not in_rule:
                header_lines.append(line)
            else:
                # We're in a rule, add to current rule
                current_rule.append(line)
    
    # Don't forget the last rule
    if current_rule:
        rule_blocks.append(current_rule)
    
    # Extract imports from header
    import_lines = []
    for line in header_lines:
        if re.match(r'^\s*import\s+"[^"]+"\s*$', line):
            import_lines.append(line.rstrip())
    
    imports_string = '\n'.join(import_lines) if import_lines else ""
    
    # Convert rule blocks to strings
    rules = []
    for rule_block in rule_blocks:
        rule_text = ''.join(rule_block).strip()
        if rule_text:
            rules.append(rule_text)
    
    return imports_string, rules


# ============================================================================
# VALIDATORS
# ============================================================================

class FileValidator:
    """Validates complete YARA files."""
    
    def __init__(self):
        self.files = []
        self.all_rule_names = {}  # Track rule names across all files: {rule_name: [file1, file2, ...]}
    
    def add_file(self, filepath):
        """Add a YARA file for validation."""
        yara_file = YaraFile(filepath)
        self.files.append(yara_file)
        return yara_file
    
    def _extract_rule_names_from_file(self, yara_file):
        """Extract all rule names from a file."""
        if not yara_file.content:
            return []
        
        rule_pattern = re.compile(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', re.MULTILINE)
        matches = rule_pattern.findall(yara_file.content)
        return matches
    
    def validate_file(self, yara_file):
        """Validate a single YARA file."""
        try:
            # Load content
            content = yara_file.load_content()
            yara_file.count_rules()
            
            # Extract rule names and track them
            rule_names = self._extract_rule_names_from_file(yara_file)
            for rule_name in rule_names:
                if rule_name not in self.all_rule_names:
                    self.all_rule_names[rule_name] = []
                self.all_rule_names[rule_name].append(yara_file.filepath)
            
            # Validate by compiling
            yara.compile(source=content)
            yara_file.status = YaraFile.STATUS_VALID
            return True
            
        except yara.Error as e:
            yara_file.status = YaraFile.STATUS_BROKEN
            yara_file.error_data = str(e)
            return False
        except Exception as e:
            yara_file.status = YaraFile.STATUS_BROKEN
            yara_file.error_data = f"Failed to process file: {str(e)}"
            return False
    
    def validate_all(self):
        """Validate all files and return categorized lists."""
        valid = []
        broken = []
        
        for yara_file in self.files:
            if self.validate_file(yara_file):
                valid.append(yara_file)
            else:
                broken.append(yara_file)
        
        return valid, broken
    
    def get_duplicate_rules(self):
        """Get all duplicate rule names across all files."""
        duplicates = {}
        for rule_name, file_list in self.all_rule_names.items():
            if len(file_list) > 1:
                duplicates[rule_name] = file_list
        return duplicates


class RuleValidator:
    """Validates individual YARA rules (split mode)."""
    
    def __init__(self, enable_deduplication=False):
        self.rules = []
        self.rule_names = {}  # Track rule names: {rule_name: [rule_obj1, rule_obj2, ...]}
        self.enable_deduplication = enable_deduplication
        self.dedup_tracker = DeduplicationTracker() if enable_deduplication else None
    
    def add_file(self, filepath):
        """Parse a file and add all its rules for validation."""
        imports, rule_sources = parse_yara_file_to_rules(filepath)
        
        rules_added = 0
        for rule_source in rule_sources:
            rule = YaraRule(
                source=rule_source,
                source_file=filepath,
                imports=imports
            )
            
            # Handle deduplication if enabled
            if self.enable_deduplication:
                should_keep, new_name, duplicate_info = self.dedup_tracker.register_rule(
                    rule.rule_name,
                    rule.source,
                    filepath
                )
                
                if not should_keep:
                    # This is a true duplicate - mark and skip
                    rule.mark_as_duplicate(duplicate_info)
                    self.rules.append(rule)  # Add to list but marked as removed
                    continue
                elif new_name:
                    # Name conflict - rename the rule
                    print(f"  🔄 Renaming: '{rule.rule_name}' → '{new_name}' in {os.path.basename(filepath)}")
                    rule.rename(new_name)
            
            self.rules.append(rule)
            rules_added += 1
            
            # Track rule name (use current name after any renaming)
            if rule.rule_name not in self.rule_names:
                self.rule_names[rule.rule_name] = []
            self.rule_names[rule.rule_name].append(rule)
        
        return rules_added
    
    def validate_rule(self, rule):
        """Validate a single rule."""
        # Skip validation for removed duplicates
        if rule.was_removed:
            rule.status = YaraRule.STATUS_VALID  # Mark as valid since it's just a duplicate
            return True
        
        try:
            full_source = rule.get_full_source()
            yara.compile(source=full_source)
            rule.status = YaraRule.STATUS_VALID
            return True
        except yara.Error as e:
            rule.status = YaraRule.STATUS_BROKEN
            rule.error_data = str(e)
            return False
    
    def validate_all(self):
        """Validate all rules and return categorized lists."""
        valid = []
        broken = []
        
        for rule in self.rules:
            if self.validate_rule(rule):
                if not rule.was_removed:  # Only include non-duplicates in valid list
                    valid.append(rule)
            else:
                broken.append(rule)
        
        return valid, broken
    
    def get_duplicate_rules(self):
        """Get all duplicate rule names (simple check, not dedup-aware)."""
        duplicates = {}
        for rule_name, rule_list in self.rule_names.items():
            if len(rule_list) > 1:
                duplicates[rule_name] = rule_list
        return duplicates
    
    def get_deduplication_report(self):
        """Get detailed deduplication report."""
        if not self.enable_deduplication or not self.dedup_tracker:
            return None
        return self.dedup_tracker


# ============================================================================
# FILE I/O OPERATIONS
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


def write_valid_files(yara_files, output_dir):
    """Write valid YARA files to output directory, preserving filenames."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        # Handle duplicate filenames
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
        # Add validation header
        header = f"// Validated: {datetime.now().isoformat()}\n"
        header += f"// Source: {yara_file.filepath}\n"
        header += f"// Rules: {yara_file.rule_count}\n"
        header += f"// Status: {yara_file.status.upper()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(yara_file.content)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_files(yara_files, output_dir):
    """Write failed YARA files to output directory with error info."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        # Handle duplicate filenames
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
        # Add error header
        header = f"// VALIDATION FAILED\n"
        header += f"// Source: {yara_file.filepath}\n"
        header += f"// Rules: {yara_file.rule_count}\n"
        header += f"// Error: {yara_file.error_data}\n"
        header += f"// Timestamp: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(yara_file.content)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_valid_rules(rules, output_dir):
    """Write valid rules to output directory as individual files."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Get full source with imports
        full_source = rule.get_full_source()
        
        # Add header
        header = f"// Rule: {rule.rule_name}\n"
        if rule.was_renamed:
            header += f"// Original Name: {rule.original_name}\n"
            header += f"// Status: RENAMED (name conflict resolved)\n"
        header += f"// Source: {rule.source_file}\n"
        header += f"// Hash: {rule.fingerprint.hash[:16]}\n"
        header += f"// Validated: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


def write_failed_rules(rules, output_dir):
    """Write failed rules to output directory with error info."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        # Handle duplicate rule names
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        
        # Get full source with imports
        full_source = rule.get_full_source()
        
        # Add error header
        header = f"// VALIDATION FAILED\n"
        header += f"// Rule: {rule.rule_name}\n"
        header += f"// Source: {rule.source_file}\n"
        header += f"// Error: {rule.error_data}\n"
        header += f"// Timestamp: {datetime.now().isoformat()}\n\n"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(full_source)
            written_files.append(output_path)
        except Exception as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
    
    return written_files


# ============================================================================
# REPORTING
# ============================================================================

def generate_file_json_report(valid_files, broken_files, duplicates, output_file):
    """Generate JSON report for file-level validation."""
    total = len(valid_files) + len(broken_files)
    total_rules = sum(f.rule_count for f in valid_files + broken_files)
    
    # Format duplicates for JSON
    duplicates_list = []
    for rule_name, file_list in duplicates.items():
        duplicates_list.append({
            'rule_name': rule_name,
            'count': len(file_list),
            'files': file_list
        })
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'file',
        'summary': {
            'total_files': total,
            'valid_files': len(valid_files),
            'broken_files': len(broken_files),
            'total_rules': total_rules,
            'duplicate_rules': len(duplicates),
            'success_rate': round(len(valid_files) / total * 100, 2) if total > 0 else 0
        },
        'duplicates': duplicates_list,
        'valid_files': [f.to_dict() for f in valid_files],
        'broken_files': [f.to_dict() for f in broken_files]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_rule_json_report(valid_rules, broken_rules, duplicates, output_file):
    """Generate JSON report for rule-level validation."""
    total = len(valid_rules) + len(broken_rules)
    
    # Format duplicates for JSON
    duplicates_list = []
    for rule_name, rule_list in duplicates.items():
        duplicates_list.append({
            'rule_name': rule_name,
            'count': len(rule_list),
            'source_files': [r.source_file for r in rule_list]
        })
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'split',
        'summary': {
            'total_rules': total,
            'valid_rules': len(valid_rules),
            'broken_rules': len(broken_rules),
            'duplicate_rules': len(duplicates),
            'success_rate': round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        },
        'duplicates': duplicates_list,
        'valid_rules': [r.to_dict() for r in valid_rules],
        'broken_rules': [r.to_dict() for r in broken_rules]
    }
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_file_markdown_report(valid_files, broken_files, duplicates, output_file):
    """Generate Markdown report for file-level validation."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA File Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** File-level validation\n\n")
        
        # Summary
        total = len(valid_files) + len(broken_files)
        total_rules = sum(file.rule_count for file in valid_files + broken_files)
        success_rate = round(len(valid_files) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Files | {total} |\n")
        f.write(f"| ✅ Valid Files | {len(valid_files)} |\n")
        f.write(f"| ❌ Broken Files | {len(broken_files)} |\n")
        f.write(f"| Total Rules | {total_rules} |\n")
        f.write(f"| ⚠️ Duplicate Rule Names | {len(duplicates)} |\n")
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_files) == 0 and len(duplicates) == 0:
            f.write("**Status:** ✅ All files validated successfully, no duplicates found\n\n")
        elif len(broken_files) > 0 and len(duplicates) > 0:
            f.write(f"**Status:** ⚠️ {len(broken_files)} file(s) failed validation AND {len(duplicates)} duplicate rule name(s) found\n\n")
        elif len(broken_files) > 0:
            f.write(f"**Status:** ⚠️ {len(broken_files)} file(s) failed validation\n\n")
        else:
            f.write(f"**Status:** ⚠️ {len(duplicates)} duplicate rule name(s) found\n\n")
        
        # Duplicate rules warning
        if duplicates:
            f.write("## ⚠️ Duplicate Rule Names\n\n")
            f.write("**CRITICAL:** YARA requires all rule names to be unique across all loaded files.\n")
            f.write("The following rule names appear in multiple files and must be renamed:\n\n")
            
            for rule_name, file_list in sorted(duplicates.items()):
                f.write(f"### ⚠️ `{rule_name}` (appears in {len(file_list)} files)\n\n")
                for filepath in file_list:
                    f.write(f"- `{filepath}`\n")
                f.write("\n")
            
            f.write("**💡 Recommendation:** Add a prefix or suffix to make rule names unique.\n")
            f.write("- Example: `MalwareRule` → `Vendor_MalwareRule` or `MalwareRule_v1`\n\n")
            f.write("---\n\n")
        
        # Valid files
        if valid_files:
            f.write("## ✅ Valid Files\n\n")
            for file in valid_files:
                f.write(f"- **{file.filename}** ({file.rule_count} rule(s)) - `{file.filepath}`\n")
            f.write("\n")
        
        # Broken files
        if broken_files:
            f.write("## ❌ Broken Files\n\n")
            for i, file in enumerate(broken_files, 1):
                f.write(f"### {i}. {file.filename}\n\n")
                f.write(f"- **Path:** `{file.filepath}`\n")
                f.write(f"- **Rules:** {file.rule_count}\n")
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{file.error_data}\n")
                f.write("```\n\n")
                
                # Show first 20 lines of content
                if file.content:
                    f.write("<details>\n")
                    f.write("<summary>View file content (first 20 lines)</summary>\n\n")
                    f.write("```yara\n")
                    lines = file.content.split('\n')
                    for line_num, line in enumerate(lines[:20], 1):
                        f.write(f"{line_num:4d}: {line}\n")
                    if len(lines) > 20:
                        f.write(f"... ({len(lines) - 20} more lines)\n")
                    f.write("```\n")
                    f.write("</details>\n\n")
                
                f.write("---\n\n")


def generate_rule_markdown_report(valid_rules, broken_rules, duplicates, output_file):
    """Generate Markdown report for rule-level validation."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA Rule Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** Split-rule validation\n\n")
        
        # Summary
        total = len(valid_rules) + len(broken_rules)
        success_rate = round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Rules | {total} |\n")
        f.write(f"| ✅ Valid Rules | {len(valid_rules)} |\n")
        f.write(f"| ❌ Broken Rules | {len(broken_rules)} |\n")
        f.write(f"| ⚠️ Duplicate Rule Names | {len(duplicates)} |\n")
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_rules) == 0 and len(duplicates) == 0:
            f.write("**Status:** ✅ All rules validated successfully, no duplicates found\n\n")
        elif len(broken_rules) > 0 and len(duplicates) > 0:
            f.write(f"**Status:** ⚠️ {len(broken_rules)} rule(s) failed validation AND {len(duplicates)} duplicate rule name(s) found\n\n")
        elif len(broken_rules) > 0:
            f.write(f"**Status:** ⚠️ {len(broken_rules)} rule(s) failed validation\n\n")
        else:
            f.write(f"**Status:** ⚠️ {len(duplicates)} duplicate rule name(s) found\n\n")
        
        # Duplicate rules warning
        if duplicates:
            f.write("## ⚠️ Duplicate Rule Names\n\n")
            f.write("**CRITICAL:** YARA requires all rule names to be unique across all loaded files.\n")
            f.write("The following rule names appear multiple times and must be renamed:\n\n")
            
            for rule_name, rule_list in sorted(duplicates.items()):
                f.write(f"### ⚠️ `{rule_name}` (appears {len(rule_list)} times)\n\n")
                for rule in rule_list:
                    f.write(f"- `{rule.source_file}`\n")
                f.write("\n")
            
            f.write("**💡 Recommendation:** Add a prefix or suffix to make rule names unique.\n")
            f.write("- Example: `MalwareRule` → `Vendor_MalwareRule` or `MalwareRule_v1`\n\n")
            f.write("---\n\n")
        
        # Valid rules
        if valid_rules:
            f.write("## ✅ Valid Rules\n\n")
            for rule in valid_rules:
                f.write(f"- **{rule.rule_name}** - `{rule.source_file}`\n")
            f.write("\n")
        
        # Broken rules
        if broken_rules:
            f.write("## ❌ Broken Rules\n\n")
            for i, rule in enumerate(broken_rules, 1):
                f.write(f"### {i}. {rule.rule_name}\n\n")
                f.write(f"- **Source:** `{rule.source_file}`\n")
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{rule.error_data}\n")
                f.write("```\n\n")
                
                # Show rule source
                f.write("<details>\n")
                f.write("<summary>View rule source</summary>\n\n")
                f.write("```yara\n")
                full_source = rule.get_full_source()
                lines = full_source.split('\n')
                for line_num, line in enumerate(lines[:30], 1):
                    f.write(f"{line_num:4d}: {line}\n")
                if len(lines) > 30:
                    f.write(f"... ({len(lines) - 30} more lines)\n")
                f.write("```\n")
                f.write("</details>\n\n")
                
                f.write("---\n\n")


def generate_rule_json_report_with_dedup(valid_rules, broken_rules, duplicates, dedup_data, output_file):
    """Generate JSON report for rule-level validation with deduplication data."""
    total = len(valid_rules) + len(broken_rules)
    
    # Format duplicates for JSON
    duplicates_list = []
    for rule_name, rule_list in duplicates.items():
        duplicates_list.append({
            'rule_name': rule_name,
            'count': len(rule_list),
            'source_files': [r.source_file for r in rule_list]
        })
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'split',
        'deduplication_enabled': dedup_data is not None,
        'summary': {
            'total_rules': total,
            'valid_rules': len(valid_rules),
            'broken_rules': len(broken_rules),
            'duplicate_rules': len(duplicates),
            'success_rate': round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        },
        'duplicates': duplicates_list,
        'valid_rules': [r.to_dict() for r in valid_rules],
        'broken_rules': [r.to_dict() for r in broken_rules]
    }
    
    # Add deduplication data if available
    if dedup_data:
        report['deduplication'] = dedup_data
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_rule_markdown_report_with_dedup(valid_rules, broken_rules, duplicates, dedup_tracker, output_file):
    """Generate Markdown report for rule-level validation with deduplication details."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA Rule Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** Split-rule validation")
        if dedup_tracker:
            f.write(" with deduplication")
        f.write("\n\n")
        
        # Summary
        total = len(valid_rules) + len(broken_rules)
        success_rate = round(len(valid_rules) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Rules | {total} |\n")
        f.write(f"| ✅ Valid Rules | {len(valid_rules)} |\n")
        f.write(f"| ❌ Broken Rules | {len(broken_rules)} |\n")
        
        if not dedup_tracker:
            f.write(f"| ⚠️ Duplicate Rule Names | {len(duplicates)} |\n")
        else:
            stats = dedup_tracker.get_statistics()
            f.write(f"| 🔄 Rules Renamed | {stats['renames']} |\n")
            f.write(f"| 🗑️ Duplicates Removed | {stats['removals']} |\n")
        
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_rules) == 0 and (not duplicates or dedup_tracker):
            f.write("**Status:** ✅ All rules validated successfully")
            if dedup_tracker:
                f.write(", duplicates handled")
            f.write("\n\n")
        else:
            if len(broken_rules) > 0:
                f.write(f"**Status:** ⚠️ {len(broken_rules)} rule(s) failed validation")
            if duplicates and not dedup_tracker:
                if len(broken_rules) > 0:
                    f.write(f" AND {len(duplicates)} duplicate rule name(s) found")
                else:
                    f.write(f"**Status:** ⚠️ {len(duplicates)} duplicate rule name(s) found")
            f.write("\n\n")
        
        # Deduplication report
        if dedup_tracker:
            stats = dedup_tracker.get_statistics()
            if stats['total_duplicates'] > 0:
                f.write("## 🔄 Deduplication Report\n\n")
                f.write(f"**Total Duplicates Found:** {stats['total_duplicates']}\n\n")
                
                # Renamed rules
                if dedup_tracker.renames:
                    f.write(f"### 📝 Renamed Rules ({len(dedup_tracker.renames)})\n\n")
                    f.write("The following rules had name conflicts and were renamed:\n\n")
                    
                    for rename in dedup_tracker.renames:
                        f.write(f"#### `{rename['original_name']}` → `{rename['new_name']}`\n\n")
                        f.write(f"- **File:** `{rename['file']}`\n")
                        f.write(f"- **Reason:** {rename['reason']}\n")
                        f.write(f"- **Original Hash:** `{rename['original_hash']}`\n")
                        f.write(f"- **New Hash:** `{rename['new_hash']}`\n\n")
                
                # Removed duplicates
                if dedup_tracker.removals:
                    f.write(f"### 🗑️ Removed Duplicates ({len(dedup_tracker.removals)})\n\n")
                    f.write("The following rules were true duplicates (identical content) and were removed:\n\n")
                    
                    for removal in dedup_tracker.removals:
                        f.write(f"#### `{removal['rule_name']}`\n\n")
                        f.write(f"- **File:** `{removal['file']}`\n")
                        f.write(f"- **Reason:** {removal['reason']}\n")
                        f.write(f"- **Hash:** `{removal['hash']}`\n\n")
                
                f.write("---\n\n")
        
        # Duplicate rules warning (if no dedup)
        if not dedup_tracker and duplicates:
            f.write("## ⚠️ Duplicate Rule Names\n\n")
            f.write("**CRITICAL:** YARA requires all rule names to be unique across all loaded files.\n")
            f.write("The following rule names appear multiple times and must be renamed:\n\n")
            
            for rule_name, rule_list in sorted(duplicates.items()):
                f.write(f"### ⚠️ `{rule_name}` (appears {len(rule_list)} times)\n\n")
                for rule in rule_list:
                    f.write(f"- `{rule.source_file}`\n")
                f.write("\n")
            
            f.write("**💡 Recommendation:** Use `--deduplicate` flag to automatically handle duplicates.\n\n")
            f.write("---\n\n")
        
        # Valid rules
        if valid_rules:
            f.write("## ✅ Valid Rules\n\n")
            for rule in valid_rules:
                suffix = ""
                if rule.was_renamed:
                    suffix = f" *(renamed from `{rule.original_name}`)*"
                f.write(f"- **{rule.rule_name}**{suffix} - `{rule.source_file}`\n")
            f.write("\n")
        
        # Broken rules
        if broken_rules:
            f.write("## ❌ Broken Rules\n\n")
            for i, rule in enumerate(broken_rules, 1):
                f.write(f"### {i}. {rule.rule_name}\n\n")
                f.write(f"- **Source:** `{rule.source_file}`\n")
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{rule.error_data}\n")
                f.write("```\n\n")
                
                # Show rule source
                f.write("<details>\n")
                f.write("<summary>View rule source</summary>\n\n")
                f.write("```yara\n")
                full_source = rule.get_full_source()
                lines = full_source.split('\n')
                for line_num, line in enumerate(lines[:30], 1):
                    f.write(f"{line_num:4d}: {line}\n")
                if len(lines) > 30:
                    f.write(f"... ({len(lines) - 30} more lines)\n")
                f.write("```\n")
                f.write("</details>\n\n")
                
                f.write("---\n\n")


# ============================================================================
# MAIN VALIDATION WORKFLOWS
# ============================================================================

def validate_files_mode(directory, verbose=False, output_valid_dir=None, 
                       output_failed_dir=None, json_report=None, markdown_report=None):
    """Validate entire files (default mode)."""
    
    print("="*80)
    print("YARA File Validator - FILE MODE")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    print("="*80)
    
    # Collect files
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    # Initialize validator
    validator = FileValidator()
    
    # Add files
    print("\n📥 Loading files...")
    for filepath in yara_files:
        try:
            validator.add_file(filepath)
            if verbose:
                print(f"  ✓ Loaded: {filepath}")
        except Exception as e:
            print(f"  ✗ Error loading {filepath}: {e}")
    
    # Validate
    print("\n🔍 Validating files...")
    valid_files, broken_files = validator.validate_all()
    
    # Check for duplicate rule names
    duplicates = validator.get_duplicate_rules()
    
    # Calculate total rules
    total_rules = sum(f.rule_count for f in valid_files + broken_files)
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid files:   {len(valid_files)}")
    print(f"❌ Broken files:  {len(broken_files)}")
    print(f"📊 Total rules:   {total_rules}")
    
    # Report duplicate rule names
    if duplicates:
        print(f"⚠️  Duplicate rule names found: {len(duplicates)}")
    
    print("="*80)
    
    # Print duplicate details
    if duplicates:
        print("\n" + "="*80)
        print(f"⚠️  DUPLICATE RULE NAMES DETECTED ({len(duplicates)} conflicts)")
        print("="*80)
        print("\nYARA requires all rule names to be unique across all loaded files.")
        print("Please rename the following duplicate rules:\n")
        
        for rule_name, file_list in sorted(duplicates.items()):
            print(f"  ⚠️  Rule '{rule_name}' appears in {len(file_list)} files:")
            for filepath in file_list:
                print(f"      - {filepath}")
            print()
        
        print("="*80)
        print("💡 TIP: Add a prefix or suffix to make rule names unique")
        print("    Example: 'MalwareRule' → 'Vendor_MalwareRule' or 'MalwareRule_v1'")
        print("="*80)
    
    # Print details if verbose
    if verbose:
        if valid_files:
            print(f"\n{'='*25} VALID FILES ({len(valid_files)}) {'='*25}")
            for file in valid_files:
                print(f"  ✓ {file.filename} ({file.rule_count} rules)")
        
        if broken_files:
            print(f"\n{'='*25} BROKEN FILES ({len(broken_files)}) {'='*25}")
            for file in broken_files:
                print(f"  ❌ {file.filename} ({file.rule_count} rules)")
                print(f"     Error: {file.error_data[:100]}...")
                print()
    
    # Write outputs
    if output_valid_dir and valid_files:
        print(f"\n📝 Writing valid files to: {output_valid_dir}")
        written = write_valid_files(valid_files, output_valid_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if output_failed_dir and broken_files:
        print(f"\n📝 Writing failed files to: {output_failed_dir}")
        written = write_failed_files(broken_files, output_failed_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        generate_file_json_report(valid_files, broken_files, duplicates, json_report)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        generate_file_markdown_report(valid_files, broken_files, duplicates, markdown_report)
    
    print("\n" + "="*80)
    if broken_files:
        print(f"⚠️  Validation completed with {len(broken_files)} file failure(s)")
    else:
        print("✅ All files validated successfully!")
    print("="*80)
    
    return len(valid_files), len(broken_files)


def validate_split_mode(directory, verbose=False, enable_deduplication=False, output_valid_dir=None,
                       output_failed_dir=None, json_report=None, markdown_report=None):
    """Validate individual rules (split mode)."""
    
    mode_name = "SPLIT MODE WITH DEDUPLICATION" if enable_deduplication else "SPLIT MODE"
    print("="*80)
    print(f"YARA Rule Validator - {mode_name}")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    if enable_deduplication:
        print(f"Deduplication: ENABLED")
    print("="*80)
    
    # Collect files
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    # Initialize validator
    validator = RuleValidator(enable_deduplication=enable_deduplication)
    
    # Parse and add rules
    print("\n📥 Parsing rules from files...")
    total_rules = 0
    for filepath in yara_files:
        try:
            rule_count = validator.add_file(filepath)
            total_rules += rule_count
            if verbose:
                print(f"  ✓ Parsed {rule_count} rule(s) from: {filepath}")
        except Exception as e:
            print(f"  ✗ Error parsing {filepath}: {e}")
    
    print(f"\n📊 Total rules parsed: {total_rules}")
    
    # Show deduplication progress if enabled
    if enable_deduplication:
        dedup_report = validator.get_deduplication_report()
        if dedup_report:
            stats = dedup_report.get_statistics()
            print(f"\n🔄 Deduplication Results:")
            print(f"   • Name conflicts resolved: {stats['name_conflicts']}")
            print(f"   • True duplicates removed: {stats['true_duplicates']}")
            print(f"   • Rules renamed: {stats['renames']}")
            print(f"   • Rules removed: {stats['removals']}")
    
    # Validate
    print("\n🔍 Validating rules...")
    valid_rules, broken_rules = validator.validate_all()
    
    # Check for duplicate rule names (simple check, may show remaining after dedup)
    duplicates = validator.get_duplicate_rules() if not enable_deduplication else {}
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid rules:   {len(valid_rules)}")
    print(f"❌ Broken rules:  {len(broken_rules)}")
    
    # Report duplicate rule names (only if deduplication not enabled)
    if not enable_deduplication and duplicates:
        print(f"⚠️  Duplicate rule names found: {len(duplicates)}")
    
    print("="*80)
    
    # Print deduplication details if verbose
    if enable_deduplication and verbose:
        dedup_report = validator.get_deduplication_report()
        if dedup_report and (dedup_report.renames or dedup_report.removals):
            print("\n" + "="*80)
            print("🔄 DETAILED DEDUPLICATION REPORT")
            print("="*80)
            
            if dedup_report.renames:
                print(f"\n📝 RENAMED RULES ({len(dedup_report.renames)}):\n")
                for rename in dedup_report.renames:
                    print(f"  🔄 '{rename['original_name']}' → '{rename['new_name']}'")
                    print(f"     File: {rename['file']}")
                    print(f"     Reason: {rename['reason']}")
                    print(f"     Hash: {rename['original_hash']} → {rename['new_hash']}")
                    print()
            
            if dedup_report.removals:
                print(f"🗑️  REMOVED DUPLICATES ({len(dedup_report.removals)}):\n")
                for removal in dedup_report.removals:
                    print(f"  ✗ '{removal['rule_name']}'")
                    print(f"     File: {removal['file']}")
                    print(f"     Reason: {removal['reason']}")
                    print(f"     Hash: {removal['hash']}")
                    print()
            
            print("="*80)
    
    # Print duplicate details (only if not using deduplication)
    if not enable_deduplication and duplicates:
        print("\n" + "="*80)
        print(f"⚠️  DUPLICATE RULE NAMES DETECTED ({len(duplicates)} conflicts)")
        print("="*80)
        print("\nYARA requires all rule names to be unique across all loaded files.")
        print("Please rename the following duplicate rules:\n")
        
        for rule_name, rule_list in sorted(duplicates.items()):
            print(f"  ⚠️  Rule '{rule_name}' appears {len(rule_list)} times:")
            for rule in rule_list:
                print(f"      - {rule.source_file}")
            print()
        
        print("="*80)
        print("💡 TIP: Use --deduplicate flag to automatically handle duplicates")
        print("    python validate_yara_rules.py ./rules --split-rules --deduplicate --output-valid-dir deduped/")
        print("="*80)
    
    # Print details if verbose
    if verbose:
        if valid_rules:
            print(f"\n{'='*25} VALID RULES ({len(valid_rules)}) {'='*25}")
            for rule in valid_rules:
                suffix = ""
                if rule.was_renamed:
                    suffix = f" (renamed from '{rule.original_name}')"
                print(f"  ✓ {rule.rule_name}{suffix} <- {os.path.basename(rule.source_file)}")
        
        if broken_rules:
            print(f"\n{'='*25} BROKEN RULES ({len(broken_rules)}) {'='*25}")
            for rule in broken_rules:
                print(f"  ❌ {rule.rule_name} <- {os.path.basename(rule.source_file)}")
                print(f"     Error: {rule.error_data[:100]}...")
                print()
    
    # Write outputs
    if output_valid_dir and valid_rules:
        print(f"\n📝 Writing valid rules to: {output_valid_dir}")
        written = write_valid_rules(valid_rules, output_valid_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if output_failed_dir and broken_rules:
        print(f"\n📝 Writing failed rules to: {output_failed_dir}")
        written = write_failed_rules(broken_rules, output_failed_dir)
        print(f"   Wrote {len(written)} file(s)")
    
    if json_report:
        print(f"\n📝 Generating JSON report: {json_report}")
        # Include deduplication data if available
        dedup_data = validator.get_deduplication_report().to_dict() if enable_deduplication else None
        generate_rule_json_report_with_dedup(valid_rules, broken_rules, duplicates, dedup_data, json_report)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        dedup_data = validator.get_deduplication_report() if enable_deduplication else None
        generate_rule_markdown_report_with_dedup(valid_rules, broken_rules, duplicates, dedup_data, markdown_report)
    
    print("\n" + "="*80)
    if broken_rules:
        print(f"⚠️  Validation completed with {len(broken_rules)} rule failure(s)")
    else:
        print("✅ All rules validated successfully!")
    
    if enable_deduplication:
        dedup_report = validator.get_deduplication_report()
        if dedup_report:
            stats = dedup_report.get_statistics()
            print(f"🔄 Deduplication: {stats['renames']} renamed, {stats['removals']} removed")
    
    print("="*80)
    
    return len(valid_rules), len(broken_rules)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='YARA Rule Validator for CI/CD Pipelines',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
OPERATION MODES:

  FILE MODE (default):
    Validates entire files as-is, preserving all rules, imports, and dependencies.
    This is the recommended mode for most use cases.
    
    Example: python %(prog)s ./rules --output-valid-dir validated/
  
  SPLIT MODE (--split-rules):
    Parses individual rules from files and validates each separately.
    Useful for isolating issues in multi-rule files.
    
    Example: python %(prog)s ./rules --split-rules --output-valid-dir validated/
  
  DEDUPLICATION (--deduplicate):
    Automatically handles duplicate rules:
    - Renames rules with name conflicts (same name, different content)
    - Removes true duplicates (same name and content)
    Only works with --split-rules mode.
    
    Example: python %(prog)s ./rules --split-rules --deduplicate --output-valid-dir deduped/

EXAMPLES:

  # Validate complete files (recommended)
  python %(prog)s ./rules --output-valid-dir validated/
  
  # Validate files with detailed output
  python %(prog)s ./rules --verbose --output-valid-dir validated/ --output-failed-dir failed/
  
  # Split and validate individual rules
  python %(prog)s ./rules --split-rules --output-valid-dir validated/
  
  # Auto-deduplicate rules (split mode)
  python %(prog)s ./rules --split-rules --deduplicate --output-valid-dir deduped/
  
  # Deduplicate with verbose output
  python %(prog)s ./rules --split-rules --deduplicate --verbose --output-valid-dir deduped/
  
  # Generate reports
  python %(prog)s ./rules --json-report report.json --markdown-report report.md
        """
    )
    
    parser.add_argument('directory', 
                       help='Directory containing YARA rule files')
    
    parser.add_argument('--split-rules', action='store_true',
                       help='Parse and validate individual rules separately (split mode)')
    
    parser.add_argument('--deduplicate', action='store_true',
                       help='Auto-deduplicate rules: rename conflicts, remove true duplicates (requires --split-rules)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output including deduplication changes')
    
    parser.add_argument('--output-valid-dir', metavar='DIR',
                       help='Output directory for valid files/rules')
    
    parser.add_argument('--output-failed-dir', metavar='DIR',
                       help='Output directory for failed files/rules')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--markdown-report', metavar='FILE',
                       help='Generate Markdown report')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.deduplicate and not args.split_rules:
        print("❌ Error: --deduplicate requires --split-rules mode", file=sys.stderr)
        print("   Use: python validate_yara_rules.py ./rules --split-rules --deduplicate", file=sys.stderr)
        sys.exit(1)
    
    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"❌ Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Choose validation mode
        if args.split_rules:
            valid_count, broken_count = validate_split_mode(
                args.directory,
                verbose=args.verbose,
                enable_deduplication=args.deduplicate,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        else:
            valid_count, broken_count = validate_files_mode(
                args.directory,
                verbose=args.verbose,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        
        # Exit codes
        # 0 = success (all valid)
        # 1 = validation failures
        # 2 = no files/rules found
        if valid_count == 0:
            sys.exit(2)
        elif broken_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"❌ Error during validation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
