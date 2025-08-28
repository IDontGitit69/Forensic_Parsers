"""
log_processor.py

This script recursively searches a given directory for log files, extracts
timestamps from various log formats using regular expressions and the dateutil
library, converts them to ISO 8601 format, filters log entries by a specified
date range, sorts the filtered entries by timestamp, and finally saves both
the unfiltered and filtered results to separate CSV files in the home directory.
It includes a progress bar to show processing progress.
"""

import os
import re
import csv
from datetime import datetime
from dateutil import parser
from dateutil.tz import tzlocal
from typing import Optional, Tuple
from tqdm import tqdm # Import tqdm for progress bars

def get_user_input():
    """Gets directory path, date range, and output filenames from the user with validation."""
    while True:
        directory_path = input("Enter the directory path to search: ")
        if directory_path:
            break
        else:
            print("Directory path cannot be empty. Please try again.")

    while True:
        start_date_str = input("Enter the start date for filtering (YYYY-MM-DD): ")
        if start_date_str:
            break
        else:
            print("Start date cannot be empty. Please try again.")

    while True:
        end_date_str = input("Enter the end date for filtering (YYYY-MM-DD): ")
        if end_date_str:
            break
        else:
            print("End date cannot be empty. Please try again.")

    while True:
        unfiltered_output_filename = input("Enter the desired filename for unfiltered output (e.g., unfiltered_logs.csv): ")
        if unfiltered_output_filename:
            break
        else:
            print("Output filename cannot be empty. Please try again.")

    while True:
        filtered_output_filename = input("Enter the desired filename for filtered output (e.g., filtered_logs.csv): ")
        if filtered_output_filename:
            break
        else:
            print("Output filename cannot be empty. Please try again.")


    return directory_path, start_date_str, end_date_str, unfiltered_output_filename, filtered_output_filename

class LogTimestampParser:
    def __init__(self):
        # Define timestamp patterns and assign a type name to each
        self.timestamp_patterns = [
            # Specific format like "Wed, 05 Mar 2025 13:11:04 +0000"
            (re.compile(r'([A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4})'), 'RFC 1123/822'),

            # ISO 8601 variants (e.g., 2024-01-15T10:30:45Z, 2024-01-15 10:30:45+00:00)
            (re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:[+-]\d{2}:?\d{2}|Z)?)'), 'ISO 8601'),

            # Common syslog formats (e.g., Jan 15 10:30:45, 2024-01-15 10:30:45)
            (re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), 'Syslog (Month Day Time)'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'), 'Syslog (YYYY-MM-DD Time)'),

            # Apache/Nginx log formats (e.g., 15/Jan/2024:10:30:45 +0000)
            (re.compile(r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})'), 'Apache/Nginx'),
            (re.compile(r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})'), 'MM/DD/YYYY Time'), # Common alternative

            # Windows Event Log style (e.g., 1/15/2024 10:30:45 AM)
            (re.compile(r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s(?:AM|PM))'), 'Windows Event Log'),

            # Unix timestamp (epoch seconds) (e.g., 1705312245 or 1705312245.123)
            (re.compile(r'(\b\d{10}(?:\.\d{1,6})?\b)'), 'Unix Timestamp'),

            # Custom application formats (e.g., 20240115 10:30:45, 15-01-2024 10:30:45)
            (re.compile(r'(\d{4}\d{2}\d{2}\s+\d{2}:\d{2}:\d{2})'), 'YYYYMMDD Time'),
            (re.compile(r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})'), 'DD-MM-YYYY Time'),

            # Time only (will use current date) (e.g., 10:30:45)
            (re.compile(r'(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)'), 'Time Only'),
        ]


    def extract_timestamp_from_line(self, line: str) -> Tuple[Optional[str], str, int, Optional[str]]:
        """
        Extract timestamp string and its type from log line
        Returns: (timestamp_string, remaining_message, start_position, timestamp_type)
        """
        line = line.strip()

        for pattern, pattern_type in self.timestamp_patterns:
            match = pattern.search(line)
            if match:
                timestamp_str = match.group(1)
                start_pos = match.start(1)
                end_pos = match.end(1)

                # Extract the message (everything except the timestamp)
                if start_pos == 0:
                    # Timestamp is at the beginning
                    message = line[end_pos:].strip()
                    # Remove common separators
                    message = re.sub(r'^[\s\-\|\:\]\}\>\)\,\;]+', '', message)
                else:
                    # Timestamp is in the middle or end
                    # Keep everything before and after, but mark where timestamp was
                    before = line[:start_pos].strip()
                    after = line[end_pos:].strip()
                    message = f"{before} {after}".strip()


                return timestamp_str, message, start_pos, pattern_type

        # No timestamp found
        return None, line, -1, None

    def parse_timestamp_string(self, timestamp_str: str, timestamp_type: Optional[str]) -> Optional[datetime]:
        """
        Parse a timestamp string to datetime object based on identified type
        """
        if not timestamp_str:
            return None

        # Attempt parsing based on identified type first for accuracy
        try:
            if timestamp_type == 'RFC 1123/822':
                 # This format needs specific handling due to variations and potential missing year or timezone
                 # Try with explicit format string first
                 try:
                    return datetime.strptime(timestamp_str.strip(), '%a, %d %b %Y %H:%M:%S %z')
                 except ValueError:
                    # Fallback to parser.parse for flexibility if explicit format fails
                    parsed = parser.parse(timestamp_str, fuzzy=True)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=tzlocal())
                    return parsed

            elif timestamp_type == 'ISO 8601':
                return parser.isoparse(timestamp_str)

            elif timestamp_type == 'Unix Timestamp':
                 try:
                    return datetime.fromtimestamp(float(timestamp_str), tz=tzlocal())
                 except (ValueError, OverflowError):
                    return None # Handle potential errors in unix timestamp conversion

            elif timestamp_type == 'Syslog (Month Day Time)':
                # Requires adding the current year for parsing
                try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%b %d %H:%M:%S')
                    today = datetime.now().date()
                    parsed = parsed.replace(year=today.year)
                    if parsed.tzinfo is None:
                         parsed = parsed.replace(tzinfo=tzlocal())
                    return parsed
                except ValueError:
                    pass # Fallback to general parsing if explicit fails

            elif timestamp_type == 'Time Only':
                 # Requires adding the current date for parsing
                 try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%H:%M:%S')
                    today = datetime.now().date()
                    parsed = parsed.replace(year=today.year, month=today.month, day=today.day)
                    if parsed.tzinfo is None:
                         parsed = parsed.replace(tzinfo=tzlocal())
                    return parsed
                 except ValueError:
                    pass # Fallback to general parsing if explicit fails


            # For other types or if type-specific parsing fails, try general parsing
            parsed = parser.parse(timestamp_str, fuzzy=True)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=tzlocal())
            return parsed

        except (ValueError, TypeError, OverflowError):
            return None # Return None if parsing fails


    def parse_log_line(self, line: str) -> Tuple[Optional[datetime], str, Optional[str]]:
        """
        Parse a single log line to extract timestamp, message, and timestamp type
        Returns: (datetime_object, original_line, timestamp_type)
        """
        timestamp_str, message, _, timestamp_type = self.extract_timestamp_from_line(line)

        if timestamp_str:
            timestamp = self.parse_timestamp_string(timestamp_str, timestamp_type)
            return timestamp, line.strip(), timestamp_type # Return original line and type
        else:
            return None, line.strip(), None # Return original line and None type


def parse_log_entries(all_log_entries, verbose=False):
    """
    Parse log entries and convert timestamps to ISO 8601 format,
    including identifying the timestamp type and if it was converted.

    Args:
        all_log_entries: List of (file_path, line) tuples
        verbose: Print debugging information

    Returns:
        List of (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted) tuples
    """
    parser_instance = LogTimestampParser()
    parsed_log_entries = []

    successful_parses = 0
    failed_parses = 0

    # Wrap the loop with tqdm for a progress bar
    for file_path, line in tqdm(all_log_entries, desc="Parsing log entries", unit="entry"):
        timestamp, original_line, timestamp_type = parser_instance.parse_log_line(line) # Get original line and type

        was_converted = False
        if timestamp_type and timestamp_type != 'ISO 8601':
            was_converted = True

        if timestamp:
            # Convert to ISO 8601 format with microsecond precision
            iso_timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
            # Ensure timezone offset is correctly formatted (e.g., +00:00 instead of +0000)
            if iso_timestamp.endswith('00') and (iso_timestamp[-5] == '+' or iso_timestamp[-5] == '-'):
                 iso_timestamp = iso_timestamp[:-2] + ':' + iso_timestamp[-2:]

            parsed_log_entries.append((file_path, iso_timestamp, original_line, timestamp_type, was_converted)) # Store original line, type, and converted status
            successful_parses += 1

            if verbose:
                conversion_status = "Converted" if was_converted else "Original ISO 8601"
                print(f"✓ Parsed ({timestamp_type}, {conversion_status}): {line[:50]}... -> {iso_timestamp}")
        else:
            # No timestamp found or couldn't parse
            parsed_log_entries.append((file_path, None, original_line, None, False)) # Store original line, None type, and False converted status
            failed_parses += 1

            if verbose:
                print(f"✗ Failed: {line[:50]}...")

    print(f"\nParsing Summary:")
    print(f"  Successfully parsed: {successful_parses}")
    print(f"  Failed to parse: {failed_parses}")
    print(f"  Total entries: {len(all_log_entries)}")

    return parsed_log_entries

def filter_log_entries_by_date(parsed_log_entries, start_date_str, end_date_str):
    """
    Filters parsed log entries by a specified date range.

    Args:
        parsed_log_entries: List of (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted) tuples.
        start_date_str: Start date string (YYYY-MM-DD).
        end_date_str: End date string (YYYY-MM-DD).

    Returns:
        List of filtered log entries.
    """
    try:
        start_date = parser.parse(start_date_str).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = parser.parse(end_date_str).replace(hour=23, minute=59, second=59, microsecond=999999)
        date_filter_valid = True
    except (ValueError, TypeError):
        print("Error: Invalid start or end date format. Filtering will not be applied.")
        date_filter_valid = False
        return parsed_log_entries # If dates are invalid, return all entries

    if not date_filter_valid:
        return parsed_log_entries

    filtered_log_entries = []
    for entry in tqdm(parsed_log_entries, desc="Filtering log entries", unit="entry"): # Wrap the loop with tqdm
        file_path, iso_timestamp, original_line, timestamp_type, was_converted = entry
        if iso_timestamp:
            try:
                # Convert the ISO 8601 timestamp string back to a datetime object for comparison
                entry_timestamp = parser.isoparse(iso_timestamp)

                # Ensure timezone awareness for comparison if needed (assuming timestamps are timezone aware)
                # If timestamps from logs might be naive, a more robust approach might be needed
                # For now, comparing timezone-aware datetimes directly is generally safe

                if start_date <= entry_timestamp.replace(tzinfo=None) <= end_date.replace(tzinfo=None): # Compare naive datetimes
                    filtered_log_entries.append(entry)
            except (ValueError, TypeError):
                # Handle cases where the ISO timestamp string itself is invalid after parsing
                print(f"Warning: Could not parse ISO timestamp for filtering: {iso_timestamp}. Skipping entry.")
                pass
        else:
            # Include entries without timestamps if you want them in the output regardless of date,
            # or exclude them if date filtering is essential.
            # Currently, they are excluded by the if iso_timestamp check.
            pass # Skip entries with no timestamp

    return filtered_log_entries

def sort_log_entries_by_timestamp(log_entries):
    """
    Sorts log entries by their ISO 8601 timestamps.

    Args:
        log_entries: List of (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted) tuples.

    Returns:
        List of sorted log entries.
    """
    # Sort the log entries by timestamp
    # The timestamp is the second element (index 1) in each tuple
    # Use datetime.min with local timezone for entries with None timestamp to place them at the beginning
    return sorted(log_entries, key=lambda x: parser.isoparse(x[1]) if x[1] else datetime.min.replace(tzinfo=tzlocal()))

def save_log_entries_to_csv(log_entries, output_file_path):
    """
    Saves log entries to a CSV file.

    Args:
        log_entries: List of (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted) tuples.
        output_file_path: Path to the output CSV file.
    """
    csv_header = ["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"]

    # Ensure the directory exists
    output_dir = os.path.dirname(output_file_path)
    if output_dir: # Check if output_dir is not an empty string (i.e., not current directory)
        os.makedirs(output_dir, exist_ok=True)

    # Write the data to the CSV file
    try:
        with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)

            # Write the header
            csv_writer.writerow(csv_header)

            # Wrap the loop with tqdm for a progress bar during saving
            for file_path, iso_timestamp, log_message, timestamp_type, was_converted in tqdm(log_entries, desc=f"Saving to {os.path.basename(output_file_path)}", unit="entry"):
                # Write each log entry as a row in the CSV
                csv_writer.writerow([file_path, iso_timestamp, log_message, timestamp_type, was_converted])

        print(f"\nSuccessfully saved log entries to '{output_file_path}'")
    except IOError as e:
        print(f"Error saving file {output_file_path}: {e}")


# Main execution flow
if __name__ == "__main__":
    # 1. Get user input for directory, date range, and output filenames
    directory_path, start_date_str, end_date_str, unfiltered_output_filename, filtered_output_filename = get_user_input()

    # 2. Find all files (potential log files) recursively in the specified directory
    log_files = []
    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            # Check if the path is actually a file (and not a directory or symlink)
            if os.path.isfile(file_path):
                log_files.append(file_path)

    print(f"\nFound {len(log_files)} potential log files.")

    # 3. Read log entries line by line from the found files
    all_log_entries = []
    # Use tqdm for a progress bar while reading files
    for file_path in tqdm(log_files, desc="Reading log files", unit="file"):
        try:
            # Open and read each file, stripping leading/trailing whitespace from each line
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    all_log_entries.append((file_path, line.strip()))
        except IOError as e:
            # Print an error message if a file cannot be read
            print(f"Error reading file {file_path}: {e}")
        except UnicodeDecodeError:
             print(f"Warning: Could not decode file {file_path} with utf-8. Skipping.")


    print(f"\nRead {len(all_log_entries)} log entries.")

    # 4. Parse log entries to extract timestamps and other information
    # Use parse_log_entries function which includes timestamp parsing and conversion to ISO 8601
    parsed_log_entries = parse_log_entries(all_log_entries, verbose=False) # Set verbose to True for detailed parsing output

    # 5. Save the unfiltered parsed log entries to a CSV file with user-specified filename
    save_log_entries_to_csv(parsed_log_entries, unfiltered_output_filename)

    # 6. Filter the parsed log entries based on the user-specified date range
    filtered_log_entries = filter_log_entries_by_date(parsed_log_entries, start_date_str, end_date_str)
    print(f"\nFiltered down to {len(filtered_log_entries)} log entries.")

    # 7. Sort the filtered log entries by their timestamp
    sorted_filtered_log_entries = sort_log_entries_by_timestamp(filtered_log_entries)
    print(f"\nSorted {len(sorted_filtered_log_entries)} filtered log entries.")

    # 8. Save the filtered and sorted log entries to a separate CSV file with user-specified filename
    save_log_entries_to_csv(sorted_filtered_log_entries, filtered_output_filename)
