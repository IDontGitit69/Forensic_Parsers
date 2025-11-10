#!/usr/bin/env python3
"""
YARA Rule Dependency Parser

This script parses YARA files and identifies rules that have dependencies
on other rules within the same file.
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


class YaraRuleParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.rules = {}
        self.dependencies = {}
        
    def parse(self):
        """Parse the YARA file and extract rules and their dependencies."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove comments
        content = self._remove_comments(content)
        
        # Find all rule definitions
        rule_pattern = r'rule\s+(\w+)\s*(?::\s*[\w\s]+)?\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(rule_pattern, content, re.DOTALL):
            rule_name = match.group(1)
            rule_body = match.group(2)
            
            self.rules[rule_name] = rule_body
            
            # Extract dependencies from the condition section
            dependencies = self._extract_dependencies(rule_body, rule_name)
            
            if dependencies:
                self.dependencies[rule_name] = dependencies
    
    def _remove_comments(self, content: str) -> str:
        """Remove single-line and multi-line comments from YARA content."""
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Remove single-line comments
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        return content
    
    def _extract_dependencies(self, rule_body: str, current_rule: str) -> Set[str]:
        """Extract rule dependencies from the condition section."""
        dependencies = set()
        
        # Find the condition section
        condition_match = re.search(r'condition\s*:(.*?)(?:$|\Z)', rule_body, re.DOTALL | re.IGNORECASE)
        
        if not condition_match:
            return dependencies
        
        condition = condition_match.group(1)
        
        # Pattern to match rule references in conditions
        # Matches: rule_name, rule_name(), rule_name[index]
        # Excludes: keywords like 'all', 'any', 'them', 'for', 'of', 'in', etc.
        rule_ref_pattern = r'\b(?!(?:all|any|them|for|of|in|and|or|not|true|false|defined|uint8|uint16|uint32|int8|int16|int32|filesize|entrypoint|at|in)\b)([a-zA-Z_]\w*)(?:\s*\(|\s*\[|\s*(?=\s|$|and|or|not|\)))'
        
        for match in re.finditer(rule_ref_pattern, condition):
            potential_rule = match.group(1)
            
            # Check if this is actually a rule name (exists in the file)
            # We'll collect all potential references and validate later
            if potential_rule != current_rule:
                dependencies.add(potential_rule)
        
        return dependencies
    
    def get_validated_dependencies(self) -> Dict[str, List[str]]:
        """Return only dependencies that reference rules actually defined in the file."""
        validated_deps = {}
        
        for rule_name, deps in self.dependencies.items():
            valid_deps = [dep for dep in deps if dep in self.rules]
            if valid_deps:
                validated_deps[rule_name] = sorted(valid_deps)
        
        return validated_deps
    
    def print_report(self):
        """Print a formatted report of rule dependencies."""
        validated_deps = self.get_validated_dependencies()
        
        if not validated_deps:
            print(f"No rule dependencies found in {self.file_path}")
            return
        
        print(f"\n{'='*70}")
        print(f"YARA Rule Dependency Report: {Path(self.file_path).name}")
        print(f"{'='*70}\n")
        
        print(f"Total rules analyzed: {len(self.rules)}")
        print(f"Rules with dependencies: {len(validated_deps)}\n")
        
        for rule_name, deps in sorted(validated_deps.items()):
            print(f"Rule: {rule_name}")
            print(f"  Dependencies: {', '.join(deps)}")
            print()
        
        # Print dependency graph
        print(f"\n{'='*70}")
        print("Dependency Graph")
        print(f"{'='*70}\n")
        
        for rule_name, deps in sorted(validated_deps.items()):
            for dep in deps:
                print(f"{rule_name} -> {dep}")
        
        print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python yara_dependency_parser.py <yara_file>")
        print("\nExample:")
        print("  python yara_dependency_parser.py rules.yar")
        sys.exit(1)
    
    yara_file = sys.argv[1]
    
    if not Path(yara_file).exists():
        print(f"Error: File '{yara_file}' not found")
        sys.exit(1)
    
    parser = YaraRuleParser(yara_file)
    
    try:
        parser.parse()
        parser.print_report()
    except Exception as e:
        print(f"Error parsing YARA file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
