"""
log_processor.py (Refactored)

Improved version with better timestamp extraction, error handling, and 
support for unstructured data from Slack and other sources.
"""

import os
import re
import csv
import argparse
from datetime import datetime, timedelta
from dateutil import parser as dateutil_parser
from dateutil.tz import tzlocal, tzutc
from typing import Optional, Tuple
from tqdm import tqdm


class LogTimestampParser:
    """
    Improved class for parsing various timestamp formats from log lines.
    Includes better validation and error handling.
    """
    def __init__(self):
        # Order matters: more specific patterns first
        self.timestamp_patterns = [
            # RFC 1123/822 with strict validation
            (re.compile(r'([A-Za-z]{3},\s+\d{2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'), 'RFC 1123/822'),

            # ISO 8601 variants - strict patterns
            (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))'), 'ISO 8601'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:\s*[+-]\d{2}:?\d{2})?)'), 'ISO 8601 (space variant)'),

            # Apache/Nginx format (strict)
            (re.compile(r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'), 'Apache/Nginx'),

            # Syslog formats with stricter patterns
            (re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?:\s|$|\D)'), 'Syslog (Month Day Time)'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:\s|$|\D)'), 'Syslog (YYYY-MM-DD Time)'),

            # Windows Event Log style (strict)
            (re.compile(r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))'), 'Windows Event Log'),

            # Custom formats
            (re.compile(r'(\d{8}\s+\d{2}:\d{2}:\d{2})'), 'YYYYMMDD Time'),
            (re.compile(r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})'), 'DD-MM-YYYY Time'),

            # Unix timestamp - with strict word boundaries and value validation
            (re.compile(r'(\b\d{10}(?:\.\d{1,6})?\b)'), 'Unix Timestamp'),

            # Time only (last resort)
            (re.compile(r'(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)'), 'Time Only'),
        ]

    def _validate_unix_timestamp(self, timestamp_str: str) -> bool:
        """
        Validate that a unix timestamp is in a reasonable range.
        
        Args:
            timestamp_str: The unix timestamp string
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ts = float(timestamp_str)
            # Check if timestamp is between 1970 and ~2100
            # 1970: 0, 2100: ~4102444800
            return 0 <= ts <= 4102444800
        except (ValueError, OverflowError):
            return False

    def extract_timestamp_from_line(self, line: str) -> Tuple[Optional[str], str, int, Optional[str]]:
        """
        Extract timestamp string and its type from log line using regex patterns.
        """
        line = line.strip()
        
        if not line:
            return None, line, -1, None

        for pattern, pattern_type in self.timestamp_patterns:
            match = pattern.search(line)
            if match:
                timestamp_str = match.group(1).strip()
                
                # Additional validation for Unix timestamps
                if pattern_type == 'Unix Timestamp':
                    if not self._validate_unix_timestamp(timestamp_str):
                        continue
                
                start_pos = match.start(1)
                end_pos = match.end(1)

                # Extract the message
                if start_pos == 0:
                    message = line[end_pos:].strip()
                    message = re.sub(r'^[\s\-\|\:\]\}\>\)\,\;]+', '', message)
                else:
                    before = line[:start_pos].strip()
                    after = line[end_pos:].strip()
                    message = f"{before} {after}".strip()

                return timestamp_str, message, start_pos, pattern_type

        return None, line, -1, None

    def parse_timestamp_string(self, timestamp_str: str, timestamp_type: Optional[str]) -> Optional[datetime]:
        """
        Parse a timestamp string to datetime object with improved error handling.
        """
        if not timestamp_str:
            return None

        try:
            if timestamp_type == 'RFC 1123/822':
                try:
                    return datetime.strptime(timestamp_str.strip(), '%a, %d %b %Y %H:%M:%S %z')
                except ValueError:
                    return dateutil_parser.parse(timestamp_str, fuzzy=False)

            elif timestamp_type == 'ISO 8601':
                return dateutil_parser.isoparse(timestamp_str)

            elif timestamp_type == 'ISO 8601 (space variant)':
                return dateutil_parser.isoparse(timestamp_str.replace(' ', 'T'))

            elif timestamp_type == 'Unix Timestamp':
                try:
                    ts = float(timestamp_str)
                    if not (0 <= ts <= 4102444800):
                        return None
                    return datetime.fromtimestamp(ts, tz=tzutc())
                except (ValueError, OverflowError, OSError):
                    return None

            elif timestamp_type == 'Syslog (Month Day Time)':
                try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%b %d %H:%M:%S')
                    today = datetime.now().date()
                    parsed = parsed.replace(year=today.year, tzinfo=tzlocal())
                    return parsed
                except ValueError:
                    pass

            elif timestamp_type == 'Time Only':
                try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%H:%M:%S')
                    today = datetime.now().date()
                    parsed = parsed.replace(year=today.year, month=today.month, day=today.day, tzinfo=tzlocal())
                    return parsed
                except ValueError:
                    pass

            # Generic parsing with strict validation
            try:
                parsed = dateutil_parser.parse(timestamp_str, fuzzy=False)
                
                # Validate the parsed datetime is reasonable
                if parsed.year < 1970 or parsed.year > 2100:
                    return None
                
                # Add timezone if missing
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=tzlocal())
                
                return parsed
            except (ValueError, TypeError, OverflowError):
                return None

        except Exception as e:
            # Catch any unexpected errors
            return None

    def parse_log_line(self, line: str) -> Tuple[Optional[datetime], str, Optional[str]]:
        """
        Parse a single log line to extract timestamp.
        """
        timestamp_str, message, _, timestamp_type = self.extract_timestamp_from_line(line)

        if timestamp_str:
            timestamp = self.parse_timestamp_string(timestamp_str, timestamp_type)
            return timestamp, line.strip(), timestamp_type
        else:
            return None, line.strip(), None


def filter_log_entries_by_date(iso_timestamp, start_date_filter, end_date_filter):
    """
    Filter a single log entry by date range.
    """
    if not iso_timestamp:
        return False

    try:
        entry_timestamp = dateutil_parser.isoparse(iso_timestamp)
        return start_date_filter <= entry_timestamp <= end_date_filter
    except (ValueError, TypeError):
        return False


def sort_log_entries_by_timestamp(log_entries):
    """
    Sort log entries by timestamp.
    """
    def get_sort_key(entry):
        iso_timestamp = entry[1]
        if iso_timestamp:
            try:
                return dateutil_parser.isoparse(iso_timestamp)
            except (ValueError, TypeError):
                return datetime.min.replace(tzinfo=tzutc())
        return datetime.min.replace(tzinfo=tzutc())

    return sorted(log_entries, key=get_sort_key)


def save_log_entries_to_csv(log_entries, output_file_path):
    """
    Save log entries to CSV file.
    """
    csv_header = ["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"]

    output_dir = os.path.dirname(output_file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    try:
        with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(csv_header)

            for entry in tqdm(log_entries, desc=f"Saving to {os.path.basename(output_file_path)}", unit="entry"):
                csv_writer.writerow(entry)

        print(f"\nSuccessfully saved {len(log_entries)} log entries to '{output_file_path}'")
    except IOError as e:
        print(f"Error saving file {output_file_path}: {e}")


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description='Recursively search log files, filter by date, and output to CSV.')
    arg_parser.add_argument('-d', '--directory', required=True, help='Directory path to search for log files.')
    arg_parser.add_argument('-s', '--start_date', required=True, help='Start date for filtering (YYYY-MM-DD).')
    arg_parser.add_argument('-e', '--end_date', required=True, help='End date for filtering (YYYY-MM-DD).')
    arg_parser.add_argument('--unfiltered_output', default='unfiltered_log_entries.csv', help='Filename for unfiltered output CSV.')
    arg_parser.add_argument('--filtered_output', default='filtered_log_entries.csv', help='Filename for filtered output CSV.')

    args = arg_parser.parse_args()

    # Parse and validate date range
    try:
        start_date_filter = dateutil_parser.parse(args.start_date).replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=tzutc())
        end_date_filter = dateutil_parser.parse(args.end_date).replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=tzutc())
    except (ValueError, TypeError):
        print("Error: Invalid date format. Please use YYYY-MM-DD.")
        exit(1)

    # Find log files
    log_files = []
    for root, _, files in tqdm(os.walk(args.directory), desc="Finding log files", unit="directory"):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                log_files.append(file_path)

    print(f"Found {len(log_files)} potential log files.")

    # Process files
    parsed_log_entries_unfiltered = []
    filtered_log_entries = []
    parser_instance = LogTimestampParser()

    unfiltered_output_path = args.unfiltered_output
    
    try:
        with open(unfiltered_output_path, 'w', newline='', encoding='utf-8') as unfiltered_file:
            unfiltered_writer = csv.writer(unfiltered_file)
            unfiltered_writer.writerow(["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"])

            for file_path in tqdm(log_files, desc="Processing files", unit="file"):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            timestamp, original_line, timestamp_type = parser_instance.parse_log_line(line.strip())

                            was_converted = bool(timestamp_type and timestamp_type != 'ISO 8601')

                            iso_timestamp = None
                            if timestamp:
                                iso_timestamp = timestamp.isoformat()

                            parsed_entry = (file_path, iso_timestamp, original_line, timestamp_type, was_converted)
                            unfiltered_writer.writerow(parsed_entry)

                            # Filter by date
                            if filter_log_entries_by_date(iso_timestamp, start_date_filter, end_date_filter):
                                filtered_log_entries.append(parsed_entry)

                except IOError as e:
                    print(f"Error reading file {file_path}: {e}")
                except Exception as e:
                    print(f"Unexpected error processing {file_path}: {e}")

    except IOError as e:
        print(f"Error opening output file: {e}")
        exit(1)

    print(f"\nProcessed and saved unfiltered entries to '{unfiltered_output_path}'")
    print(f"Collected {len(filtered_log_entries)} entries within date range.")

    # Sort and save filtered entries
    print("\nSorting filtered log entries...")
    sorted_filtered_log_entries = sort_log_entries_by_timestamp(filtered_log_entries)

    filtered_output_path = args.filtered_output
    save_log_entries_to_csv(sorted_filtered_log_entries, filtered_output_path)

    print("\nLog processing complete.")
