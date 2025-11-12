#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
YARA Rule Validator for CI/CD Pipelines

This script validates YARA rule files with multiple operation modes and features:

1. FILE MODE (Default): Validates entire files as-is, preserving all rules, imports, 
   and dependencies together. This is the recommended mode for most use cases.

2. SPLIT MODE (--split-rules): Parses individual rules from files and validates each 
   separately. Useful for isolating issues in multi-rule files.

FEATURES:
- Advanced Duplicate Handling: Detects and auto-deduplicates rules
- Metadata Validation: Enforces required metadata fields and formats
- Detailed Reporting: JSON and Markdown reports with comprehensive statistics

Usage:
    # Validate with metadata enforcement
    python validate_yara_rules.py <directory> --require-metadata --output-valid-dir validated/
    
    # Auto-deduplicate and validate metadata
    python validate_yara_rules.py <directory> --deduplicate --require-metadata --output-valid-dir clean/

Examples:
    # Standard validation
    python validate_yara_rules.py ./rules --output-valid-dir validated/
    
    # With metadata requirements
    python validate_yara_rules.py ./rules --require-metadata --output-valid-dir validated/
    
    # Full cleanup: deduplicate + metadata validation
    python validate_yara_rules.py ./rules --deduplicate --require-metadata --output-valid-dir clean/
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
# METADATA VALIDATION CONFIGURATION
# ============================================================================

# Required metadata fields
REQUIRED_METADATA_FIELDS = [
    'author',
    'date',
    'last_modified',
    'category',
    'description',
    'classification',
    'scope',
    'platform'
]

# Fields with restricted values
METADATA_VALUE_RESTRICTIONS = {
    'classification': ['Hunting', 'Production', 'Experimental'],
    'scope': ['file', 'memory', 'process', 'network'],
    'platform': ['windows', 'linux', 'macos', 'generic']
}

# Date format patterns
DATE_PATTERNS = {
    'date': r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
    'last_modified': r'^\d{8}_\d{4}$'  # YYYYMMDD_HHMM
}


# ============================================================================
# METADATA VALIDATION
# ============================================================================

class MetadataValidationError:
    """Represents a metadata validation error."""
    
    TYPE_MISSING_FIELD = 'missing_field'
    TYPE_INVALID_FORMAT = 'invalid_format'
    TYPE_INVALID_VALUE = 'invalid_value'
    TYPE_EMPTY_VALUE = 'empty_value'
    
    def __init__(self, error_type, field_name, message, expected_value=None, actual_value=None):
        self.error_type = error_type
        self.field_name = field_name
        self.message = message
        self.expected_value = expected_value
        self.actual_value = actual_value
    
    def to_dict(self):
        result = {
            'type': self.error_type,
            'field': self.field_name,
            'message': self.message
        }
        if self.expected_value:
            result['expected'] = self.expected_value
        if self.actual_value is not None:
            result['actual'] = self.actual_value
        return result
    
    def __str__(self):
        return f"{self.field_name}: {self.message}"


class MetadataValidator:
    """Validates YARA rule metadata against required template."""
    
    def __init__(self):
        self.errors = []
    
    def extract_metadata(self, rule_source):
        """
        Extract metadata section from YARA rule source.
        Returns: dict of {field_name: value}
        """
        metadata = {}
        
        # Find the meta: section
        meta_match = re.search(r'meta:\s*(.*?)(?:strings:|condition:|\})', 
                              rule_source, re.DOTALL | re.IGNORECASE)
        
        if not meta_match:
            return metadata
        
        meta_content = meta_match.group(1)
        
        # Parse metadata fields (handle both quoted and unquoted values)
        field_pattern = r'(\w+)\s*=\s*(?:"([^"]*)"|(\S+))'
        
        for match in re.finditer(field_pattern, meta_content):
            field_name = match.group(1)
            # Use quoted value if present, otherwise use unquoted value
            field_value = match.group(2) if match.group(2) is not None else match.group(3)
            metadata[field_name] = field_value
        
        return metadata
    
    def validate_metadata(self, rule_source, rule_name='unknown'):
        """
        Validate metadata in a YARA rule.
        Returns: (is_valid, list_of_errors)
        """
        self.errors = []
        metadata = self.extract_metadata(rule_source)
        
        # Check for required fields
        for field in REQUIRED_METADATA_FIELDS:
            if field not in metadata:
                self.errors.append(MetadataValidationError(
                    MetadataValidationError.TYPE_MISSING_FIELD,
                    field,
                    f"Required metadata field '{field}' is missing"
                ))
            else:
                value = metadata[field].strip()
                
                # Check if value is empty
                if not value:
                    self.errors.append(MetadataValidationError(
                        MetadataValidationError.TYPE_EMPTY_VALUE,
                        field,
                        f"Metadata field '{field}' is empty",
                        actual_value=value
                    ))
                    continue
                
                # Validate date formats
                if field in DATE_PATTERNS:
                    pattern = DATE_PATTERNS[field]
                    if not re.match(pattern, value):
                        expected_format = "YYYY-MM-DD" if field == 'date' else "YYYYMMDD_HHMM"
                        self.errors.append(MetadataValidationError(
                            MetadataValidationError.TYPE_INVALID_FORMAT,
                            field,
                            f"Date format invalid for '{field}' (expected: {expected_format})",
                            expected_value=expected_format,
                            actual_value=value
                        ))
                
                # Validate restricted values
                if field in METADATA_VALUE_RESTRICTIONS:
                    allowed_values = METADATA_VALUE_RESTRICTIONS[field]
                    if value not in allowed_values:
                        self.errors.append(MetadataValidationError(
                            MetadataValidationError.TYPE_INVALID_VALUE,
                            field,
                            f"Invalid value for '{field}' (must be one of: {', '.join(allowed_values)})",
                            expected_value=allowed_values,
                            actual_value=value
                        ))
        
        is_valid = len(self.errors) == 0
        return is_valid, self.errors
    
    def get_metadata_template(self):
        """Return a string showing the required metadata template."""
        template = """meta:
    author = ""
    date = "YYYY-MM-DD"
    last_modified = "YYYYMMDD_HHMM"
    category = ""
    description = ""
    classification = "Hunting | Production | Experimental"
    scope = "file | memory | process | network"
    platform = "windows | linux | macos | generic"
"""
        return template


# ============================================================================
# RULE FINGERPRINTING AND DEDUPLICATION
# ============================================================================

class RuleFingerprint:
    """Computes and stores a hash fingerprint of a YARA rule's content."""
    
    def __init__(self, rule_source):
        self.rule_source = rule_source
        self.hash = self._compute_hash()
    
    def _compute_hash(self):
        '''
        Compute SHA256 hash of normalized rule content (excluding rule name).
        This allows detection of identical rules with different names.
        '''
        match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+\w+\s*(\{.*\})', 
                        self.rule_source, re.DOTALL | re.MULTILINE)
        
        if match:
            rule_body = match.group(1)
        else:
            rule_body = self.rule_source
        
        normalized = re.sub(r'\s+', ' ', rule_body.strip())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    
    def __eq__(self, other):
        return isinstance(other, RuleFingerprint) and self.hash == other.hash
    
    def __hash__(self):
        return hash(self.hash)
    
    def __str__(self):
        return self.hash[:16]


class DuplicateInfo:
    """Tracks information about duplicate rules."""
    
    TYPE_NAME_CONFLICT = 'name_conflict'
    TYPE_TRUE_DUPLICATE = 'true_duplicate'
    TYPE_CONTENT_DUPLICATE = 'content_duplicate'
    
    def __init__(self, rule_name, duplicate_type, original_file, original_hash, original_name=None):
        self.rule_name = rule_name
        self.duplicate_type = duplicate_type
        self.original_file = original_file
        self.original_hash = original_hash
        self.original_name = original_name
        self.occurrences = []
    
    def add_occurrence(self, file_path, rule_hash, renamed_to=None):
        """Add an occurrence of this duplicate."""
        self.occurrences.append({
            'file': file_path,
            'hash': rule_hash,
            'renamed_to': renamed_to,
            'action': 'renamed' if renamed_to else 'removed'
        })
    
    def to_dict(self):
        result = {
            'rule_name': self.rule_name,
            'type': self.duplicate_type,
            'original_file': self.original_file,
            'original_hash': self.original_hash[:16],
            'occurrences': self.occurrences
        }
        if self.original_name:
            result['original_name'] = self.original_name
        return result


class DeduplicationTracker:
    """Tracks all deduplication actions across the entire validation."""
    
    def __init__(self):
        self.rule_registry = {}
        self.hash_registry = {}
        self.duplicates = []
        self.renames = []
        self.removals = []
        self.intra_file_dupes = defaultdict(list)
    
    def register_rule(self, rule_name, rule_content, file_path):
        '''
        Register a rule and check for duplicates.
        Returns: (should_keep, new_name_if_renamed, duplicate_info)
        '''
        fingerprint = RuleFingerprint(rule_content)
        rule_hash = fingerprint.hash
        
        if rule_hash in self.hash_registry:
            existing_names = self.hash_registry[rule_hash]
            if existing_names:
                original_name = existing_names[0]
                original_rule = self.rule_registry[original_name]
                
                if rule_name == original_name:
                    duplicate_info = DuplicateInfo(
                        rule_name, 
                        DuplicateInfo.TYPE_TRUE_DUPLICATE,
                        original_rule['file'],
                        original_rule['hash']
                    )
                    duplicate_info.add_occurrence(file_path, rule_hash, renamed_to=None)
                    self.duplicates.append(duplicate_info)
                    self.removals.append({
                        'rule_name': rule_name,
                        'file': file_path,
                        'reason': f'True duplicate - identical name and content to rule in {original_rule["file"]}',
                        'hash': rule_hash[:16],
                        'duplicate_type': 'true_duplicate'
                    })
                    return False, None, duplicate_info
                else:
                    duplicate_info = DuplicateInfo(
                        rule_name,
                        DuplicateInfo.TYPE_CONTENT_DUPLICATE,
                        original_rule['file'],
                        original_rule['hash'],
                        original_name=original_name
                    )
                    duplicate_info.add_occurrence(file_path, rule_hash, renamed_to=None)
                    self.duplicates.append(duplicate_info)
                    self.removals.append({
                        'rule_name': rule_name,
                        'file': file_path,
                        'reason': f'Content duplicate - identical rule body to "{original_name}" in {original_rule["file"]} (only rule name differs)',
                        'hash': rule_hash[:16],
                        'original_name': original_name,
                        'duplicate_type': 'content_duplicate'
                    })
                    return False, None, duplicate_info
        
        if rule_name in self.rule_registry:
            existing = self.rule_registry[rule_name]
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
                'reason': f'Name conflict - different rule with same name exists in {existing["file"]}',
                'original_hash': existing['hash'][:16],
                'new_hash': rule_hash[:16],
                'duplicate_type': 'name_conflict'
            })
            
            self.rule_registry[new_name] = {
                'hash': rule_hash,
                'file': file_path,
                'content': rule_content
            }
            
            if rule_hash not in self.hash_registry:
                self.hash_registry[rule_hash] = []
            self.hash_registry[rule_hash].append(new_name)
            
            return True, new_name, duplicate_info
        else:
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
        true_duplicates = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_TRUE_DUPLICATE)
        content_duplicates = sum(1 for d in self.duplicates if d.duplicate_type == DuplicateInfo.TYPE_CONTENT_DUPLICATE)
        
        return {
            'total_duplicates': len(self.duplicates),
            'name_conflicts': name_conflicts,
            'true_duplicates': true_duplicates,
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
        self.was_deduplicated = False
        self.metadata_errors = []
    
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
        result = {
            'filepath': self.filepath,
            'filename': self.filename,
            'status': self.status,
            'rule_count': self.rule_count,
            'error': self.error_data
        }
        if self.was_deduplicated:
            result['deduplicated'] = True
        if self.metadata_errors:
            result['metadata_errors'] = self.metadata_errors
        return result
    
    def __repr__(self):
        suffix = " (deduplicated)" if self.was_deduplicated else ""
        return f"<YaraFile {self.filename} - {self.status} - {self.rule_count} rules{suffix}>"


class YaraRule:
    """Represents a single YARA rule with validation status."""
    
    STATUS_UNKNOWN = 'unknown'
    STATUS_VALID = 'valid'
    STATUS_BROKEN = 'broken'
    
    def __init__(self, source, source_file='', rule_name='', imports=''):
        self.source = source
        self.source_file = source_file
        self.rule_name = rule_name or self._extract_name()
        self.original_name = self.rule_name
        self.imports = imports
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.fingerprint = RuleFingerprint(source)
        self.was_renamed = False
        self.was_removed = False
        self.duplicate_info = None
        self.metadata_errors = []
    
    def _extract_name(self):
        """Extract the rule name from source code."""
        match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', self.source, re.MULTILINE)
        return match.group(1) if match else "unknown_rule"
    
    def rename(self, new_name):
        """Rename this rule and update its source."""
        self.was_renamed = True
        self.original_name = self.rule_name
        self.rule_name = new_name
        
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
            if self.duplicate_info:
                result['duplicate_type'] = self.duplicate_info.duplicate_type
        
        if self.metadata_errors:
            result['metadata_errors'] = [e.to_dict() for e in self.metadata_errors]
        
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


# ===========================================================================
# VALIDATORS WITH METADATA SUPPORT
# ============================================================================

class FileValidator:
    """Validates complete YARA files."""
    
    def __init__(self, enable_deduplication=False, require_metadata=False):
        self.files = []
        self.all_rule_names = {}
        self.enable_deduplication = enable_deduplication
        self.require_metadata = require_metadata
        self.dedup_tracker = DeduplicationTracker() if enable_deduplication else None
        self.metadata_validator = MetadataValidator() if require_metadata else None
    
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
    
    def _validate_file_metadata(self, yara_file):
        """Validate metadata for all rules in a file."""
        if not self.require_metadata:
            return True
        
        imports, rule_sources = parse_yara_file_to_rules(yara_file.filepath)
        has_errors = False
        
        for rule_source in rule_sources:
            rule_name_match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', rule_source, re.MULTILINE)
            if not rule_name_match:
                continue
            
            rule_name = rule_name_match.group(1)
            is_valid, errors = self.metadata_validator.validate_metadata(rule_source, rule_name)
            
            if not is_valid:
                has_errors = True
                yara_file.metadata_errors.append({
                    'rule_name': rule_name,
                    'errors': [e.to_dict() for e in errors]
                })
        
        return not has_errors
    
    def _deduplicate_file_content(self, yara_file):
        """Deduplicate rules within a file's content."""
        if not self.enable_deduplication or not yara_file.content:
            return yara_file.content, False
        
        imports, rule_sources = parse_yara_file_to_rules(yara_file.filepath)
        
        kept_rules = []
        changed = False
        
        for rule_source in rule_sources:
            rule_name_match = re.search(r'(?i)^\s*(?:private\s+|global\s+)?rule\s+(\w+)', rule_source, re.MULTILINE)
            if not rule_name_match:
                kept_rules.append(rule_source)
                continue
            
            rule_name = rule_name_match.group(1)
            
            should_keep, new_name, duplicate_info = self.dedup_tracker.register_rule(
                rule_name,
                rule_source,
                yara_file.filepath
            )
            
            if not should_keep:
                changed = True
                if duplicate_info and duplicate_info.duplicate_type == DuplicateInfo.TYPE_CONTENT_DUPLICATE:
                    print(f"  🗑️  Removing content duplicate: '{rule_name}' (identical to '{duplicate_info.original_name}') from {os.path.basename(yara_file.filepath)}")
                else:
                    print(f"  🗑️  Removing duplicate: '{rule_name}' from {os.path.basename(yara_file.filepath)}")
                continue
            elif new_name:
                changed = True
                print(f"  🔄 Renaming: '{rule_name}' → '{new_name}' in {os.path.basename(yara_file.filepath)}")
                
                renamed_source = re.sub(
                    r'(?i)(^\s*(?:private\s+|global\s+)?rule\s+)(\w+)',
                    r'\g<1>' + new_name,
                    rule_source,
                    count=1,
                    flags=re.MULTILINE
                )
                kept_rules.append(renamed_source)
            else:
                kept_rules.append(rule_source)
        
        if changed:
            header = "// This file has been processed for deduplication\n"
            header += f"// Original: {yara_file.filepath}\n"
            header += f"// Processed: {datetime.now().isoformat()}\n\n"
            
            new_content = header
            
            if imports:
                new_content += imports + "\n\n"
            
            new_content += "\n\n".join(kept_rules)
            
            return new_content, True
        else:
            return yara_file.content, False
    
    def validate_file(self, yara_file):
        """Validate a single YARA file."""
        try:
            content = yara_file.load_content()
            yara_file.count_rules()
            
            # Deduplicate if enabled
            if self.enable_deduplication:
                deduplicated_content, was_changed = self._deduplicate_file_content(yara_file)
                if was_changed:
                    yara_file.content = deduplicated_content
                    yara_file.was_deduplicated = True
                    yara_file.count_rules()
            
            # Validate metadata if required
            metadata_valid = self._validate_file_metadata(yara_file)
            
            # Extract rule names
            rule_names = self._extract_rule_names_from_file(yara_file)
            for rule_name in rule_names:
                if rule_name not in self.all_rule_names:
                    self.all_rule_names[rule_name] = []
                self.all_rule_names[rule_name].append(yara_file.filepath)
            
            # Compile to validate YARA syntax
            yara.compile(source=yara_file.content)
            
            # If metadata validation failed, treat as broken
            if not metadata_valid:
                yara_file.status = YaraFile.STATUS_BROKEN
                # Format metadata errors into error_data
                error_msgs = []
                for rule_error in yara_file.metadata_errors:
                    error_msgs.append(f"Rule '{rule_error['rule_name']}' - Metadata validation failed:")
                    for err in rule_error['errors']:
                        error_msgs.append(f"  • {err['message']}")
                yara_file.error_data = "\n".join(error_msgs)
                return False
            
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
    
    def get_deduplication_report(self):
        """Get detailed deduplication report."""
        if not self.enable_deduplication or not self.dedup_tracker:
            return None
        return self.dedup_tracker


class RuleValidator:
    """Validates individual YARA rules (split mode)."""
    
    def __init__(self, enable_deduplication=False, require_metadata=False):
        self.rules = []
        self.rule_names = {}
        self.enable_deduplication = enable_deduplication
        self.require_metadata = require_metadata
        self.dedup_tracker = DeduplicationTracker() if enable_deduplication else None
        self.metadata_validator = MetadataValidator() if require_metadata else None
    
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
            
            if self.enable_deduplication:
                should_keep, new_name, duplicate_info = self.dedup_tracker.register_rule(
                    rule.rule_name,
                    rule.source,
                    filepath
                )
                
                if not should_keep:
                    rule.mark_as_duplicate(duplicate_info)
                    self.rules.append(rule)
                    
                    if duplicate_info.duplicate_type == DuplicateInfo.TYPE_CONTENT_DUPLICATE:
                        print(f"  🗑️  Removing content duplicate: '{rule.rule_name}' (identical to '{duplicate_info.original_name}') from {os.path.basename(filepath)}")
                    else:
                        print(f"  🗑️  Removing duplicate: '{rule.rule_name}' from {os.path.basename(filepath)}")
                    continue
                elif new_name:
                    print(f"  🔄 Renaming: '{rule.rule_name}' → '{new_name}' in {os.path.basename(filepath)}")
                    rule.rename(new_name)
            
            self.rules.append(rule)
            rules_added += 1
            
            if rule.rule_name not in self.rule_names:
                self.rule_names[rule.rule_name] = []
            self.rule_names[rule.rule_name].append(rule)
        
        return rules_added
    
    def validate_rule(self, rule):
        """Validate a single rule."""
        if rule.was_removed:
            rule.status = YaraRule.STATUS_VALID
            return True
        
        try:
            # Validate metadata if required
            if self.require_metadata:
                is_valid, errors = self.metadata_validator.validate_metadata(rule.source, rule.rule_name)
                if not is_valid:
                    rule.status = YaraRule.STATUS_BROKEN
                    rule.metadata_errors = errors
                    # Format metadata errors into error_data
                    error_msgs = [f"Metadata validation failed:"]
                    for err in errors:
                        error_msgs.append(f"  • {err}")
                    rule.error_data = "\n".join(error_msgs)
                    return False
            
            # Compile to validate YARA syntax
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
                if not rule.was_removed:
                    valid.append(rule)
            else:
                broken.append(rule)
        
        return valid, broken
    
    def get_duplicate_rules(self):
        """Get all duplicate rule names."""
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
    """Write valid YARA files to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
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
    """Write failed YARA files to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    
    for yara_file in yara_files:
        output_path = os.path.join(output_dir, yara_file.filename)
        
        counter = 1
        base_name = Path(yara_file.filename).stem
        ext = Path(yara_file.filename).suffix
        while os.path.exists(output_path):
            output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
            counter += 1
        
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
    """Write valid rules to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        full_source = rule.get_full_source()
        
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
    """Write failed rules to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    written_files = []
    rule_name_counts = {}
    
    for rule in rules:
        base_filename = rule.rule_name
        
        if base_filename in rule_name_counts:
            rule_name_counts[base_filename] += 1
            output_filename = f"{base_filename}_{rule_name_counts[base_filename]}.yar"
        else:
            rule_name_counts[base_filename] = 1
            output_filename = f"{base_filename}.yar"
        
        output_path = os.path.join(output_dir, output_filename)
        full_source = rule.get_full_source()
        
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
# REPORTING FUNCTIONS
# ============================================================================

def generate_json_report(valid_files_or_rules, broken_files_or_rules, duplicates, dedup_data, 
                        output_file, mode='file', require_metadata=False):
    """Generate JSON report for validation."""
    total = len(valid_files_or_rules) + len(broken_files_or_rules)
    
    if mode == 'file':
        total_rules = sum(f.rule_count for f in valid_files_or_rules + broken_files_or_rules)
    else:
        total_rules = total
    
    # Format duplicates
    duplicates_list = []
    if mode == 'file':
        for rule_name, file_list in duplicates.items():
            duplicates_list.append({
                'rule_name': rule_name,
                'count': len(file_list),
                'files': file_list
            })
    else:
        for rule_name, rule_list in duplicates.items():
            duplicates_list.append({
                'rule_name': rule_name,
                'count': len(rule_list),
                'source_files': [r.source_file for r in rule_list]
            })
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': mode,
        'metadata_validation_enabled': require_metadata,
        'summary': {
            'total_files' if mode == 'file' else 'total_rules': total,
            'valid': len(valid_files_or_rules),
            'broken': len(broken_files_or_rules),
            'total_rules': total_rules if mode == 'file' else None,
            'duplicate_rules': len(duplicates),
            'success_rate': round(len(valid_files_or_rules) / total * 100, 2) if total > 0 else 0
        },
        'duplicates': duplicates_list,
        'valid': [item.to_dict() for item in valid_files_or_rules],
        'broken': [item.to_dict() for item in broken_files_or_rules]
    }
    
    # Remove None values
    report['summary'] = {k: v for k, v in report['summary'].items() if v is not None}
    
    # Add deduplication data if available
    if dedup_data:
        report['deduplication'] = dedup_data
    
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report


def generate_markdown_report(valid_files_or_rules, broken_files_or_rules, duplicates, dedup_tracker, 
                            output_file, mode='file', require_metadata=False):
    """Generate Markdown report for validation."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# YARA Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** {'File-level' if mode == 'file' else 'Rule-level'} validation")
        if dedup_tracker:
            f.write(" with deduplication")
        if require_metadata:
            f.write(" + metadata validation")
        f.write("\n\n")
        
        # Summary
        total = len(valid_files_or_rules) + len(broken_files_or_rules)
        success_rate = round(len(valid_files_or_rules) / total * 100, 2) if total > 0 else 0
        
        f.write("## Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        if mode == 'file':
            total_rules = sum(item.rule_count for item in valid_files_or_rules + broken_files_or_rules)
            f.write(f"| Total Files | {total} |\n")
            f.write(f"| ✅ Valid Files | {len(valid_files_or_rules)} |\n")
            f.write(f"| ❌ Broken Files | {len(broken_files_or_rules)} |\n")
            f.write(f"| Total Rules | {total_rules} |\n")
        else:
            f.write(f"| Total Rules | {total} |\n")
            f.write(f"| ✅ Valid Rules | {len(valid_files_or_rules)} |\n")
            f.write(f"| ❌ Broken Rules | {len(broken_files_or_rules)} |\n")
        
        if not dedup_tracker and duplicates:
            f.write(f"| ⚠️ Duplicate Rule Names | {len(duplicates)} |\n")
        elif dedup_tracker:
            stats = dedup_tracker.get_statistics()
            f.write(f"| 🔄 Rules Renamed | {stats['renames']} |\n")
            f.write(f"| 🗑️ Duplicates Removed | {stats['removals']} |\n")
            if stats['content_duplicates'] > 0:
                f.write(f"| 📋 Content Duplicates | {stats['content_duplicates']} |\n")
        
        f.write(f"| Success Rate | {success_rate}% |\n\n")
        
        # Status
        if len(broken_files_or_rules) == 0 and (not duplicates or dedup_tracker):
            f.write("**Status:** ✅ All validated successfully")
            if dedup_tracker:
                f.write(", duplicates handled")
            f.write("\n\n")
        else:
            if len(broken_files_or_rules) > 0:
                f.write(f"**Status:** ⚠️ {len(broken_files_or_rules)} failure(s)")
            if duplicates and not dedup_tracker:
                if len(broken_files_or_rules) > 0:
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
                
                if dedup_tracker.renames:
                    f.write(f"### 📝 Renamed Rules ({len(dedup_tracker.renames)})\n\n")
                    for rename in dedup_tracker.renames:
                        f.write(f"#### `{rename['original_name']}` → `{rename['new_name']}`\n\n")
                        f.write(f"- **File:** `{rename['file']}`\n")
                        f.write(f"- **Reason:** {rename['reason']}\n\n")
                
                if dedup_tracker.removals:
                    content_dupes = [r for r in dedup_tracker.removals if r.get('duplicate_type') == 'content_duplicate']
                    true_dupes = [r for r in dedup_tracker.removals if r.get('duplicate_type') == 'true_duplicate']
                    
                    if content_dupes:
                        f.write(f"### 📋 Content Duplicates ({len(content_dupes)})\n\n")
                        for removal in content_dupes:
                            f.write(f"#### `{removal['rule_name']}`\n\n")
                            f.write(f"- **File:** `{removal['file']}`\n")
                            f.write(f"- **Identical To:** `{removal['original_name']}`\n")
                            f.write(f"- **Reason:** {removal['reason']}\n\n")
                    
                    if true_dupes:
                        f.write(f"### 🗑️ True Duplicates ({len(true_dupes)})\n\n")
                        for removal in true_dupes:
                            f.write(f"#### `{removal['rule_name']}`\n\n")
                            f.write(f"- **File:** `{removal['file']}`\n")
                            f.write(f"- **Reason:** {removal['reason']}\n\n")
                
                f.write("---\n\n")
        
        # Duplicate rules warning (if no dedup)
        if not dedup_tracker and duplicates:
            f.write("## ⚠️ Duplicate Rule Names\n\n")
            f.write("**CRITICAL:** YARA requires all rule names to be unique.\n\n")
            
            for rule_name, item_list in sorted(duplicates.items()):
                count = len(item_list)
                f.write(f"### ⚠️ `{rule_name}` (appears {count} times)\n\n")
                if mode == 'file':
                    for filepath in item_list:
                        f.write(f"- `{filepath}`\n")
                else:
                    for rule in item_list:
                        f.write(f"- `{rule.source_file}`\n")
                f.write("\n")
            
            f.write("**💡 Recommendation:** Use `--deduplicate` flag.\n\n")
            f.write("---\n\n")
        
        # Valid items
        if valid_files_or_rules:
            f.write(f"## ✅ Valid {'Files' if mode == 'file' else 'Rules'}\n\n")
            for item in valid_files_or_rules:
                if mode == 'file':
                    suffix = " *(deduplicated)*" if item.was_deduplicated else ""
                    f.write(f"- **{item.filename}** ({item.rule_count} rule(s)){suffix} - `{item.filepath}`\n")
                else:
                    suffix = ""
                    if item.was_renamed:
                        suffix = f" *(renamed from `{item.original_name}`)*"
                    f.write(f"- **{item.rule_name}**{suffix} - `{item.source_file}`\n")
            f.write("\n")
        
        # Broken items
        if broken_files_or_rules:
            f.write(f"## ❌ Broken {'Files' if mode == 'file' else 'Rules'}\n\n")
            for i, item in enumerate(broken_files_or_rules, 1):
                if mode == 'file':
                    f.write(f"### {i}. {item.filename}\n\n")
                    f.write(f"- **Path:** `{item.filepath}`\n")
                    f.write(f"- **Rules:** {item.rule_count}\n")
                else:
                    f.write(f"### {i}. {item.rule_name}\n\n")
                    f.write(f"- **Source:** `{item.source_file}`\n")
                
                f.write(f"- **Error:**\n")
                f.write("```\n")
                f.write(f"{item.error_data}\n")
                f.write("```\n\n")
                
                # Add detailed metadata errors if present
                if item.metadata_errors:
                    f.write("#### 📋 Metadata Validation Errors\n\n")
                    if mode == 'file':
                        # For files, show errors grouped by rule
                        for rule_error in item.metadata_errors:
                            f.write(f"**Rule: `{rule_error['rule_name']}`**\n\n")
                            for err in rule_error['errors']:
                                f.write(f"- **{err['field']}**: {err['message']}\n")
                                if 'expected' in err:
                                    if isinstance(err['expected'], list):
                                        f.write(f"  - Expected one of: `{', '.join(err['expected'])}`\n")
                                    else:
                                        f.write(f"  - Expected format: `{err['expected']}`\n")
                                if 'actual' in err:
                                    f.write(f"  - Actual value: `{err['actual']}`\n")
                            f.write("\n")
                    else:
                        # For individual rules, show errors directly
                        for err in item.metadata_errors:
                            err_dict = err.to_dict() if hasattr(err, 'to_dict') else err
                            f.write(f"- **{err_dict['field']}**: {err_dict['message']}\n")
                            if 'expected' in err_dict:
                                if isinstance(err_dict['expected'], list):
                                    f.write(f"  - Expected one of: `{', '.join(err_dict['expected'])}`\n")
                                else:
                                    f.write(f"  - Expected format: `{err_dict['expected']}`\n")
                            if 'actual' in err_dict:
                                f.write(f"  - Actual value: `{err_dict['actual']}`\n")
                        f.write("\n")
                
                # Show content preview
                if mode == 'file' and item.content:
                    f.write("<details>\n")
                    f.write("<summary>View file content (first 20 lines)</summary>\n\n")
                    f.write("```yara\n")
                    lines = item.content.split('\n')
                    for line_num, line in enumerate(lines[:20], 1):
                        f.write(f"{line_num:4d}: {line}\n")
                    if len(lines) > 20:
                        f.write(f"... ({len(lines) - 20} more lines)\n")
                    f.write("```\n")
                    f.write("</details>\n\n")
                elif mode == 'split':
                    f.write("<details>\n")
                    f.write("<summary>View rule source</summary>\n\n")
                    f.write("```yara\n")
                    full_source = item.get_full_source()
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

def validate_files_mode(directory, verbose=False, enable_deduplication=False, require_metadata=False,
                       output_valid_dir=None, output_failed_dir=None,
                       json_report=None, markdown_report=None):
    """Validate entire files (default mode)."""
    
    mode_parts = []
    mode_parts.append("FILE MODE")
    if enable_deduplication:
        mode_parts.append("DEDUPLICATION")
    if require_metadata:
        mode_parts.append("METADATA VALIDATION")
    mode_name = " + ".join(mode_parts)
    
    print("="*80)
    print(f"YARA File Validator - {mode_name}")
    print("="*80)
    print(f"Directory: {os.path.abspath(directory)}")
    try:
        print(f"YARA Version: {yara.__version__}")
    except:
        print("YARA Version: Unknown")
    if enable_deduplication:
        print(f"Deduplication: ENABLED")
    if require_metadata:
        print(f"Metadata Validation: ENABLED")
        print(f"Required Fields: {', '.join(REQUIRED_METADATA_FIELDS)}")
    print("="*80)
    
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    validator = FileValidator(enable_deduplication=enable_deduplication, require_metadata=require_metadata)
    
    print("\n📥 Loading files...")
    for filepath in yara_files:
        try:
            validator.add_file(filepath)
            if verbose:
                print(f"  ✓ Loaded: {filepath}")
        except Exception as e:
            print(f"  ✗ Error loading {filepath}: {e}")
    
    print("\n🔍 Validating files...")
    if enable_deduplication:
        print("    (Deduplicating rules within each file...)")
    if require_metadata:
        print("    (Checking metadata requirements...)")
    
    valid_files, broken_files = validator.validate_all()
    duplicates = validator.get_duplicate_rules()
    total_rules = sum(f.rule_count for f in valid_files + broken_files)
    
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid files:           {len(valid_files)}")
    print(f"❌ Broken files:          {len(broken_files)}")
    print(f"📊 Total rules:           {total_rules}")
    
    if not enable_deduplication and duplicates:
        print(f"⚠️  Duplicate rule names:  {len(duplicates)}")
    elif enable_deduplication:
        dedup_report = validator.get_deduplication_report()
        if dedup_report:
            stats = dedup_report.get_statistics()
            print(f"🔄 Deduplication: {stats['renames']} renamed, {stats['removals']} removed")
            if stats['content_duplicates'] > 0:
                print(f"📋 Content duplicates: {stats['content_duplicates']}")
    
    print("="*80)
    
    # Show metadata error details in verbose mode
    if require_metadata and verbose and broken_files:
        has_metadata_errors = any(f.metadata_errors for f in broken_files)
        if has_metadata_errors:
            print("\n" + "="*80)
            print(f"⚠️  METADATA VALIDATION FAILURES")
            print("="*80)
            for yara_file in broken_files:
                if yara_file.metadata_errors:
                    print(f"\n📄 {yara_file.filename}:")
                    for rule_error in yara_file.metadata_errors:
                        print(f"   Rule '{rule_error['rule_name']}':")
                        for err in rule_error['errors']:
                            print(f"      • {err['message']}")
            print("="*80)
    
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
        dedup_data = validator.get_deduplication_report().to_dict() if enable_deduplication else None
        generate_json_report(valid_files, broken_files, duplicates, dedup_data, 
                           json_report, mode='file', require_metadata=require_metadata)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        dedup_data = validator.get_deduplication_report() if enable_deduplication else None
        generate_markdown_report(valid_files, broken_files, duplicates, dedup_data, 
                               markdown_report, mode='file', require_metadata=require_metadata)
    
    print("\n" + "="*80)
    if broken_files:
        print(f"⚠️  Validation completed with {len(broken_files)} failure(s)")
    else:
        print("✅ All files validated successfully!")
    
    if enable_deduplication:
        dedup_report = validator.get_deduplication_report()
        if dedup_report:
            stats = dedup_report.get_statistics()
            print(f"🔄 Deduplication: {stats['renames']} renamed, {stats['removals']} removed")
            if stats['content_duplicates'] > 0:
                print(f"📋 Content duplicates: {stats['content_duplicates']}")
    
    print("="*80)
    
    return len(valid_files), len(broken_files)


def validate_split_mode(directory, verbose=False, enable_deduplication=False, require_metadata=False,
                       output_valid_dir=None, output_failed_dir=None,
                       json_report=None, markdown_report=None):
    """Validate individual rules (split mode)."""
    
    mode_parts = []
    mode_parts.append("SPLIT MODE")
    if enable_deduplication:
        mode_parts.append("DEDUPLICATION")
    if require_metadata:
        mode_parts.append("METADATA VALIDATION")
    mode_name = " + ".join(mode_parts)
    
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
    if require_metadata:
        print(f"Metadata Validation: ENABLED")
        print(f"Required Fields: {', '.join(REQUIRED_METADATA_FIELDS)}")
    print("="*80)
    
    yara_files = collect_yara_files(directory)
    
    if not yara_files:
        print(f"\n❌ No YARA rule files found in {directory}")
        return 0, 0
    
    print(f"\n📁 Found {len(yara_files)} YARA file(s)")
    
    validator = RuleValidator(enable_deduplication=enable_deduplication, require_metadata=require_metadata)
    
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
    
    print("\n🔍 Validating rules...")
    valid_rules, broken_rules = validator.validate_all()
    duplicates = validator.get_duplicate_rules() if not enable_deduplication else {}
    
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print(f"✅ Valid rules:           {len(valid_rules)}")
    print(f"❌ Broken rules:          {len(broken_rules)}")
    
    if not enable_deduplication and duplicates:
        print(f"⚠️  Duplicate rule names:  {len(duplicates)}")
    
    print("="*80)
    
    # Show metadata error details in verbose mode
    if require_metadata and verbose and broken_rules:
        has_metadata_errors = any(r.metadata_errors for r in broken_rules)
        if has_metadata_errors:
            print("\n" + "="*80)
            print(f"⚠️  METADATA VALIDATION FAILURES")
            print("="*80)
            for rule in broken_rules:
                if rule.metadata_errors:
                    print(f"\n📜 {rule.rule_name}:")
                    for err in rule.metadata_errors:
                        print(f"   • {err}")
            print("="*80)
    
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
        dedup_data = validator.get_deduplication_report().to_dict() if enable_deduplication else None
        generate_json_report(valid_rules, broken_rules, duplicates, dedup_data, 
                           json_report, mode='split', require_metadata=require_metadata)
    
    if markdown_report:
        print(f"\n📝 Generating Markdown report: {markdown_report}")
        dedup_data = validator.get_deduplication_report() if enable_deduplication else None
        generate_markdown_report(valid_rules, broken_rules, duplicates, dedup_data, 
                               markdown_report, mode='split', require_metadata=require_metadata)
    
    print("\n" + "="*80)
    if broken_rules:
        print(f"⚠️  Validation completed with {len(broken_rules)} failure(s)")
    else:
        print("✅ All rules validated successfully!")
    print("="*80)
    
    return len(valid_rules), len(broken_rules)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='YARA Rule Validator with Metadata Enforcement',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
OPERATION MODES:

  FILE MODE (default):
    Validates entire files as-is, preserving all rules, imports, and dependencies.
    
  SPLIT MODE (--split-rules):
    Parses individual rules from files and validates each separately.
  
FEATURES:

  DEDUPLICATION (--deduplicate):
    Automatically handles duplicate rules:
    - Renames rules with name conflicts (same name, different content)
    - Removes true duplicates (same name and content)
    - Removes content duplicates (identical rules with different names)
    
  METADATA VALIDATION (--require-metadata):
    Enforces required metadata fields:
    - author, date, last_modified, category, description
    - classification (must be: Hunting | Production | Experimental)
    - scope (must be: file | memory | process | network)
    - platform (must be: windows | linux | macos | generic)
    
    Date formats:
    - date: YYYY-MM-DD
    - last_modified: YYYYMMDD_HHMM

EXAMPLES:

  # Basic validation
  python %(prog)s ./rules --output-valid-dir validated/
  
  # With metadata enforcement
  python %(prog)s ./rules --require-metadata --output-valid-dir validated/
  
  # Full cleanup: deduplicate + metadata validation
  python %(prog)s ./rules --deduplicate --require-metadata --output-valid-dir clean/
  
  # Show metadata template
  python %(prog)s ./rules --show-metadata-template
        """
    )
    
    parser.add_argument('directory', 
                       help='Directory containing YARA rule files')
    
    parser.add_argument('--split-rules', action='store_true',
                       help='Parse and validate individual rules separately')
    
    parser.add_argument('--deduplicate', action='store_true',
                       help='Auto-deduplicate rules')
    
    parser.add_argument('--require-metadata', action='store_true',
                       help='Enforce required metadata fields and formats')
    
    parser.add_argument('--show-metadata-template', action='store_true',
                       help='Show required metadata template and exit')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    
    parser.add_argument('--output-valid-dir', metavar='DIR',
                       help='Output directory for valid files/rules')
    
    parser.add_argument('--output-failed-dir', metavar='DIR',
                       help='Output directory for failed files/rules (syntax or metadata errors)')
    
    parser.add_argument('--json-report', metavar='FILE',
                       help='Generate JSON report')
    
    parser.add_argument('--markdown-report', metavar='FILE',
                       help='Generate Markdown report')
    
    args = parser.parse_args()
    
    # Show metadata template if requested
    if args.show_metadata_template:
        validator = MetadataValidator()
        print("="*80)
        print("REQUIRED METADATA TEMPLATE")
        print("="*80)
        print(validator.get_metadata_template())
        print("="*80)
        print("\nREQUIRED FIELDS:")
        for field in REQUIRED_METADATA_FIELDS:
            print(f"  • {field}")
        print("\nRESTRICTED VALUES:")
        for field, values in METADATA_VALUE_RESTRICTIONS.items():
            print(f"  • {field}: {', '.join(values)}")
        print("\nDATE FORMATS:")
        print("  • date: YYYY-MM-DD (e.g., 2024-03-15)")
        print("  • last_modified: YYYYMMDD_HHMM (e.g., 20240315_1430)")
        print("="*80)
        sys.exit(0)
    
    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"❌ Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    try:
        if args.split_rules:
            valid_count, broken_count = validate_split_mode(
                args.directory,
                verbose=args.verbose,
                enable_deduplication=args.deduplicate,
                require_metadata=args.require_metadata,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        else:
            valid_count, broken_count = validate_files_mode(
                args.directory,
                verbose=args.verbose,
                enable_deduplication=args.deduplicate,
                require_metadata=args.require_metadata,
                output_valid_dir=args.output_valid_dir,
                output_failed_dir=args.output_failed_dir,
                json_report=args.json_report,
                markdown_report=args.markdown_report
            )
        
        # Exit codes
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
