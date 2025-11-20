#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Validation Report Generator

Aggregates all validation stage reports into comprehensive final reports.
Generates both JSON and Markdown formats with complete pipeline statistics.

Usage:
    python generate_report.py \
        --baseline reports/baseline_check.json \
        --syntax reports/syntax_validation.json \
        --metadata reports/metadata_validation.json \
        --dedup reports/deduplication.json \
        --database reports/database_update.json \
        --output-json final_report.json \
        --output-markdown final_report.md
"""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path


class ReportAggregator:
    """Aggregates validation reports from all pipeline stages."""
    
    def __init__(self):
        self.baseline_data = None
        self.syntax_data = None
        self.metadata_data = None
        self.dedup_data = None
        self.database_data = None
        self.errors = []
    
    def load_report(self, filepath, stage_name):
        """Load a JSON report file."""
        if not filepath:
            return None
        
        if not os.path.exists(filepath):
            self.errors.append(f"⚠️  {stage_name} report not found: {filepath}")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.errors.append(f"❌ Error loading {stage_name} report: {e}")
            return None
    
    def load_all_reports(self, baseline_path, syntax_path, metadata_path, dedup_path, database_path):
        """Load all report files."""
        print("="*80)
        print("YARA Validation Report Aggregator")
        print("="*80)
        print("Loading reports...")
        
        self.baseline_data = self.load_report(baseline_path, "Baseline Check")
        self.syntax_data = self.load_report(syntax_path, "Syntax Validation")
        self.metadata_data = self.load_report(metadata_path, "Metadata Validation")
        self.dedup_data = self.load_report(dedup_path, "Deduplication")
        self.database_data = self.load_report(database_path, "Database Update")
        
        # Print load status
        reports_loaded = sum([
            self.baseline_data is not None,
            self.syntax_data is not None,
            self.metadata_data is not None,
            self.dedup_data is not None,
            self.database_data is not None
        ])
        
        print(f"✅ Loaded {reports_loaded}/5 reports")
        
        if self.errors:
            print("\n⚠️  Warnings:")
            for error in self.errors:
                print(f"   {error}")
        
        print("="*80)
        
        return reports_loaded > 0
    
    def calculate_summary(self):
        """Calculate overall summary statistics."""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'pipeline_status': 'success',
            'total_rules_submitted': 0,
            'rules_in_baseline': 0,
            'rules_validated': 0,
            'syntax_errors': 0,
            'metadata_errors': 0,
            'duplicates_handled': 0,
            'rules_added_to_database': 0,
            'rules_rejected': 0
        }
        
        # Baseline check stats
        if self.baseline_data:
            stats = self.baseline_data.get('statistics', {})
            summary['total_rules_submitted'] = stats.get('total_rules', 0)
            summary['rules_in_baseline'] = stats.get('existing_rules', 0)
        
        # Syntax validation stats
        if self.syntax_data:
            stats = self.syntax_data.get('statistics', {})
            summary['syntax_errors'] = stats.get('failed_files', 0)
        
        # Metadata validation stats
        if self.metadata_data:
            stats = self.metadata_data.get('statistics', {})
            summary['metadata_errors'] = stats.get('failed', 0)
        
        # Deduplication stats
        if self.dedup_data:
            dedup_stats = self.dedup_data.get('deduplication', {}).get('statistics', {})
            summary['duplicates_handled'] = dedup_stats.get('total_duplicates', 0)
        
        # Database update stats
        if self.database_data:
            stats = self.database_data.get('statistics', {})
            summary['rules_added_to_database'] = stats.get('total_added', 0)
        
        # Calculate rejected rules
        summary['rules_rejected'] = (
            summary['syntax_errors'] + 
            summary['metadata_errors']
        )
        
        # Determine pipeline status
        if summary['rules_rejected'] > 0:
            summary['pipeline_status'] = 'partial'
        
        return summary
    
    def generate_json_report(self):
        """Generate comprehensive JSON report."""
        summary = self.calculate_summary()
        
        report = {
            'generated': datetime.now().isoformat(),
            'summary': summary,
            'stages': {}
        }
        
        # Add each stage's data
        if self.baseline_data:
            report['stages']['baseline_check'] = self.baseline_data
        
        if self.syntax_data:
            report['stages']['syntax_validation'] = self.syntax_data
        
        if self.metadata_data:
            report['stages']['metadata_validation'] = self.metadata_data
        
        if self.dedup_data:
            report['stages']['deduplication'] = self.dedup_data
        
        if self.database_data:
            report['stages']['database_update'] = self.database_data
        
        # Add any errors encountered
        if self.errors:
            report['warnings'] = self.errors
        
        return report
    
    def generate_markdown_report(self):
        """Generate comprehensive Markdown report."""
        summary = self.calculate_summary()
        
        lines = []
        
        # Header
        lines.append("# YARA Validation Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Pipeline status
        if summary['pipeline_status'] == 'success':
            status_icon = "✅"
            status_text = "Success"
        else:
            status_icon = "⚠️"
            status_text = "Partial Success"
        
        lines.append(f"**Pipeline Status:** {status_icon} {status_text}")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Executive Summary
        lines.append("## 📊 Executive Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Rules Submitted | {summary['total_rules_submitted']} |")
        lines.append(f"| Already in Baseline | {summary['rules_in_baseline']} |")
        lines.append(f"| New Rules Validated | {summary['total_rules_submitted'] - summary['rules_in_baseline']} |")
        lines.append(f"| Syntax Errors | {summary['syntax_errors']} |")
        lines.append(f"| Metadata Errors | {summary['metadata_errors']} |")
        lines.append(f"| Duplicates Handled | {summary['duplicates_handled']} |")
        lines.append(f"| Successfully Added to Database | {summary['rules_added_to_database']} |")
        lines.append(f"| Total Rejected | {summary['rules_rejected']} |")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Stage 1: Baseline Check
        if self.baseline_data:
            lines.extend(self._generate_baseline_section())
        
        # Stage 2: Syntax Validation
        if self.syntax_data:
            lines.extend(self._generate_syntax_section())
        
        # Stage 3: Metadata Validation
        if self.metadata_data:
            lines.extend(self._generate_metadata_section())
        
        # Stage 4: Deduplication
        if self.dedup_data:
            lines.extend(self._generate_dedup_section())
        
        # Stage 5: Database Update
        if self.database_data:
            lines.extend(self._generate_database_section())
        
        # Final Results
        lines.extend(self._generate_final_results(summary))
        
        # Warnings
        if self.errors:
            lines.append("---")
            lines.append("")
            lines.append("## ⚠️ Warnings")
            lines.append("")
            for error in self.errors:
                lines.append(f"- {error}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _generate_baseline_section(self):
        """Generate baseline check section."""
        lines = []
        stats = self.baseline_data.get('statistics', {})
        
        lines.append("## 🔍 Stage 1: Baseline Check")
        lines.append("")
        
        if stats.get('existing_rules', 0) == 0 and stats.get('new_rules', 0) > 0:
            lines.append("**Status:** ✅ All rules are new")
        elif stats.get('new_rules', 0) == 0:
            lines.append("**Status:** ℹ️ All rules already in baseline")
        else:
            lines.append("**Status:** ✅ Complete")
        
        lines.append("")
        lines.append(f"- Total rules checked: {stats.get('total_rules', 0)}")
        lines.append(f"- ⏭️ Already in baseline: {stats.get('existing_rules', 0)} (skipped validation)")
        lines.append(f"- ✅ New rules: {stats.get('new_rules', 0)} (proceeding to validation)")
        lines.append("")
        
        # Show existing rules if any
        existing_rules = self.baseline_data.get('existing_rules', [])
        if existing_rules:
            lines.append("### Rules Already in Baseline")
            lines.append("")
            for rule in existing_rules[:10]:  # Show first 10
                lines.append(f"- `{rule['rule_name']}` → Already exists as `{rule['existing_name']}` in `{os.path.basename(rule['existing_file'])}`")
            
            if len(existing_rules) > 10:
                lines.append(f"- ... and {len(existing_rules) - 10} more")
            lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
    
    def _generate_syntax_section(self):
        """Generate syntax validation section."""
        lines = []
        stats = self.syntax_data.get('statistics', {})
        
        lines.append("## ✅ Stage 2: Syntax Validation")
        lines.append("")
        
        if stats.get('failed_files', 0) == 0:
            lines.append("**Status:** ✅ All rules passed")
        else:
            lines.append(f"**Status:** ⚠️ Partial ({stats.get('failed_files', 0)} failures)")
        
        lines.append("")
        lines.append(f"- Valid files: {stats.get('valid_files', 0)}")
        lines.append(f"- Failed files: {stats.get('failed_files', 0)}")
        lines.append(f"- Total rules: {stats.get('total_rules', 0)}")
        lines.append("")
        
        # Show failed files
        failed_files = self.syntax_data.get('failed_files', [])
        if failed_files:
            lines.append("### Failed Syntax Validation")
            lines.append("")
            for i, failed in enumerate(failed_files, 1):
                lines.append(f"#### {i}. `{failed['filename']}`")
                lines.append("")
                lines.append(f"**Error:**")
                lines.append("```")
                lines.append(failed.get('error', 'Unknown error'))
                lines.append("```")
                lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
    
    def _generate_metadata_section(self):
        """Generate metadata validation section."""
        lines = []
        stats = self.metadata_data.get('statistics', {})
        
        lines.append("## 📋 Stage 3: Metadata Validation")
        lines.append("")
        
        if stats.get('failed', 0) == 0:
            lines.append("**Status:** ✅ All metadata valid")
        else:
            lines.append(f"**Status:** ⚠️ Partial ({stats.get('failed', 0)} failures)")
        
        lines.append("")
        lines.append(f"- Valid metadata: {stats.get('passed', 0)}")
        lines.append(f"- Failed metadata: {stats.get('failed', 0)}")
        lines.append("")
        
        # Show failed metadata
        failed_rules = self.metadata_data.get('failed_rules', [])
        if failed_rules:
            lines.append("### Failed Metadata Validation")
            lines.append("")
            for failed in failed_rules[:5]:  # Show first 5
                lines.append(f"#### Rule: `{failed['rule_name']}`")
                lines.append("")
                lines.append(f"**File:** `{failed.get('file', 'unknown')}`")
                lines.append("")
                lines.append("**Errors:**")
                for error in failed.get('errors', []):
                    lines.append(f"- ❌ **{error.get('field', 'unknown')}**: {error.get('message', 'Unknown error')}")
                    if 'expected' in error:
                        if isinstance(error['expected'], list):
                            lines.append(f"  - Expected one of: `{', '.join(error['expected'])}`")
                        else:
                            lines.append(f"  - Expected format: `{error['expected']}`")
                    if 'actual' in error:
                        lines.append(f"  - Actual value: `{error['actual']}`")
                lines.append("")
            
            if len(failed_rules) > 5:
                lines.append(f"... and {len(failed_rules) - 5} more metadata failures")
                lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
    
    def _generate_dedup_section(self):
        """Generate deduplication section."""
        lines = []
        dedup_info = self.dedup_data.get('deduplication', {})
        stats = dedup_info.get('statistics', {})
        
        lines.append("## 🔄 Stage 4: Deduplication")
        lines.append("")
        
        if stats.get('total_duplicates', 0) == 0:
            lines.append("**Status:** ✅ No duplicates found")
        else:
            lines.append("**Status:** ✅ Complete")
        
        lines.append("")
        lines.append(f"- Total duplicates found: {stats.get('total_duplicates', 0)}")
        lines.append(f"- Rules renamed: {stats.get('renames', 0)} (name conflicts)")
        lines.append(f"- Rules removed: {stats.get('removals', 0)} (content duplicates)")
        lines.append("")
        
        # Show renames
        renames = dedup_info.get('renames', [])
        if renames:
            lines.append("### Rules Renamed (Name Conflicts)")
            lines.append("")
            for rename in renames[:10]:
                lines.append(f"- `{rename['original_name']}` → `{rename['new_name']}`")
                lines.append(f"  - File: `{rename['file']}`")
                lines.append(f"  - Reason: {rename['reason']}")
            
            if len(renames) > 10:
                lines.append(f"- ... and {len(renames) - 10} more renames")
            lines.append("")
        
        # Show removals
        removals = dedup_info.get('removals', [])
        if removals:
            lines.append("### Rules Removed (Content Duplicates)")
            lines.append("")
            for removal in removals[:10]:
                lines.append(f"- `{removal['rule_name']}`")
                lines.append(f"  - File: `{removal['file']}`")
                if 'original_name' in removal:
                    lines.append(f"  - Duplicate of: `{removal['original_name']}`")
                lines.append(f"  - Reason: {removal['reason']}")
            
            if len(removals) > 10:
                lines.append(f"- ... and {len(removals) - 10} more removals")
            lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
    
    def _generate_database_section(self):
        """Generate database update section."""
        lines = []
        stats = self.database_data.get('statistics', {})
        
        lines.append("## 💾 Stage 5: Database Update")
        lines.append("")
        lines.append("**Status:** ✅ Complete")
        lines.append("")
        lines.append(f"- Rules added to database: {stats.get('total_added', 0)}")
        lines.append(f"- Rules skipped (already in DB): {stats.get('total_skipped', 0)}")
        lines.append("")
        
        # Show added rules
        added_rules = self.database_data.get('added_rules', [])
        if added_rules:
            lines.append("### Rules Added to Database")
            lines.append("")
            
            # Group by file
            files = {}
            for rule in added_rules:
                file = os.path.basename(rule['file'])
                if file not in files:
                    files[file] = []
                files[file].append(rule['rule_name'])
            
            for file, rules in files.items():
                lines.append(f"#### `{file}` ({len(rules)} rules)")
                lines.append("")
                for rule_name in rules[:20]:  # Show first 20
                    lines.append(f"- `{rule_name}`")
                if len(rules) > 20:
                    lines.append(f"- ... and {len(rules) - 20} more")
                lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
    
    def _generate_final_results(self, summary):
        """Generate final results section."""
        lines = []
        
        lines.append("## 📈 Final Results")
        lines.append("")
        
        success_count = summary['rules_added_to_database']
        rejected_count = summary['rules_rejected']
        skipped_count = summary['rules_in_baseline']
        
        lines.append(f"**✅ Successfully Processed: {success_count} rules**")
        lines.append(f"**❌ Rejected: {rejected_count} rules**")
        lines.append(f"**⏭️ Skipped (already in baseline): {skipped_count} rules**")
        lines.append("")
        
        # Success rate
        total_new = summary['total_rules_submitted'] - summary['rules_in_baseline']
        if total_new > 0:
            success_rate = (success_count / total_new) * 100
            lines.append(f"**Success Rate:** {success_rate:.1f}%")
            lines.append("")
        
        # Summary by outcome
        if success_count > 0:
            lines.append("### ✅ Successfully Added to Baseline")
            lines.append("")
            if self.database_data:
                added_rules = self.database_data.get('added_rules', [])
                files = {}
                for rule in added_rules:
                    file = os.path.basename(rule['file'])
                    if file not in files:
                        files[file] = 0
                    files[file] += 1
                
                for file, count in files.items():
                    lines.append(f"- `{file}` ({count} rules)")
            lines.append("")
        
        if rejected_count > 0:
            lines.append("### ❌ Rejected Rules")
            lines.append("")
            
            if self.syntax_data:
                failed_files = self.syntax_data.get('failed_files', [])
                if failed_files:
                    lines.append("**Syntax Errors:**")
                    for failed in failed_files:
                        lines.append(f"- `{failed['filename']}` - Syntax error")
                    lines.append("")
            
            if self.metadata_data:
                failed_rules = self.metadata_data.get('failed_rules', [])
                if failed_rules:
                    lines.append("**Metadata Errors:**")
                    for failed in failed_rules[:5]:
                        lines.append(f"- `{failed['rule_name']}` - Metadata validation failed")
                    if len(failed_rules) > 5:
                        lines.append(f"- ... and {len(failed_rules) - 5} more")
                    lines.append("")
        
        lines.append("---")
        lines.append("")
        
        # Recommendations
        if rejected_count > 0:
            lines.append("## 💡 Recommendations")
            lines.append("")
            lines.append("Rules were rejected due to validation failures. Please review:")
            lines.append("")
            lines.append("1. **Syntax Errors**: Check YARA syntax in rejected files")
            lines.append("2. **Metadata Errors**: Ensure all required metadata fields are present and correctly formatted")
            lines.append("3. **Refer to rejected files** in the appropriate directories for details")
            lines.append("")
        
        return lines


def main():
    parser = argparse.ArgumentParser(
        description='Aggregate YARA validation reports into comprehensive final report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  
  # Generate complete report from all stages
  python %(prog)s \\
      --baseline reports/baseline_check.json \\
      --syntax reports/syntax_validation.json \\
      --metadata reports/metadata_validation.json \\
      --dedup reports/deduplication.json \\
      --database reports/database_update.json \\
      --output-json validation_report.json \\
      --output-markdown validation_report.md
  
  # Generate report from available stages (missing stages will be skipped)
  python %(prog)s \\
      --syntax reports/syntax_validation.json \\
      --metadata reports/metadata_validation.json \\
      --output-markdown validation_report.md
        """
    )
    
    parser.add_argument('--baseline', metavar='FILE',
                       help='Baseline check JSON report')
    
    parser.add_argument('--syntax', metavar='FILE',
                       help='Syntax validation JSON report')
    
    parser.add_argument('--metadata', metavar='FILE',
                       help='Metadata validation JSON report')
    
    parser.add_argument('--dedup', metavar='FILE',
                       help='Deduplication JSON report')
    
    parser.add_argument('--database', metavar='FILE',
                       help='Database update JSON report')
    
    parser.add_argument('--output-json', metavar='FILE',
                       help='Output JSON report file')
    
    parser.add_argument('--output-markdown', metavar='FILE',
                       help='Output Markdown report file')
    
    args = parser.parse_args()
    
    # Require at least one input and one output
    if not any([args.baseline, args.syntax, args.metadata, args.dedup, args.database]):
        parser.error("At least one input report must be specified")
    
    if not args.output_json and not args.output_markdown:
        parser.error("At least one output format must be specified (--output-json or --output-markdown)")
    
    try:
        # Create aggregator
        aggregator = ReportAggregator()
        
        # Load all reports
        success = aggregator.load_all_reports(
            args.baseline,
            args.syntax,
            args.metadata,
            args.dedup,
            args.database
        )
        
        if not success:
            print("❌ Failed to load any reports")
            sys.exit(1)
        
        print("\n🔨 Generating reports...")
        
        # Generate JSON report
        if args.output_json:
            json_report = aggregator.generate_json_report()
            
            # Save JSON report
            report_dir = os.path.dirname(args.output_json)
            if report_dir:
                os.makedirs(report_dir, exist_ok=True)
            
            with open(args.output_json, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2)
            
            print(f"✅ JSON report saved: {args.output_json}")
        
        # Generate Markdown report
        if args.output_markdown:
            markdown_report = aggregator.generate_markdown_report()
            
            # Save Markdown report
            report_dir = os.path.dirname(args.output_markdown)
            if report_dir:
                os.makedirs(report_dir, exist_ok=True)
            
            with open(args.output_markdown, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            
            print(f"✅ Markdown report saved: {args.output_markdown}")
        
        print("\n" + "="*80)
        print("✅ Report generation complete!")
        print("="*80)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
