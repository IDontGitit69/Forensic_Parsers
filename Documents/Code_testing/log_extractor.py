"""
log_processor.py

This script recursively searches a given directory for log files, extracts
timestamps from various log formats using regular expressions and the dateutil
library, converts them to ISO 8601 format, filters log entries by a specified
date range, sorts the filtered entries by timestamp, and finally saves both
the unfiltered and filtered results to separate CSV files in the directory
where the script is executed. It includes a progress bar to show processing progress.
"""

import os
import re
import csv
import argparse # Import the argparse library
from datetime import datetime
from dateutil import parser as dateutil_parser # Import dateutil.parser as dateutil_parser to avoid name conflict
from dateutil.tz import tzlocal
from typing import Optional, Tuple
from tqdm import tqdm # Import tqdm for progress bars

class LogTimestampParser:
    """
    A class to handle parsing of various timestamp formats from log lines.
    """
    def __init__(self):
        # Define timestamp patterns and assign a type name to each
        # The order of patterns matters; more specific patterns should be checked first.
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
        Extract timestamp string and its type from log line using regex patterns.

        Args:
            line: The log line string.

        Returns:
            Tuple containing:
            - Optional[str]: The extracted timestamp string, or None if not found.
            - str: The remaining log message after removing the timestamp.
            - int: The starting position of the timestamp in the original line, or -1.
            - Optional[str]: The identified type of the timestamp pattern, or None.
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
        Parse a timestamp string to datetime object based on identified type.

        Args:
            timestamp_str: The timestamp string to parse.
            timestamp_type: The identified type of the timestamp pattern.

        Returns:
            Optional[datetime]: The parsed datetime object, or None if parsing fails.
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
                    # Fallback to dateutil_parser.parse for flexibility if explicit format fails
                    parsed = dateutil_parser.parse(timestamp_str, fuzzy=True)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=tzlocal())
                    return parsed

            elif timestamp_type == 'ISO 8601':
                return dateutil_parser.isoparse(timestamp_str)

            elif timestamp_type == 'Unix Timestamp':
                 try:
                    # Convert Unix timestamp (seconds since epoch) to datetime
                    return datetime.fromtimestamp(float(timestamp_str), tz=tzlocal())
                 except (ValueError, OverflowError):
                    return None # Handle potential errors in unix timestamp conversion

            elif timestamp_type == 'Syslog (Month Day Time)':
                # Handle Syslog format explicitly, adding the current year
                try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%b %d %H:%M:%S')
                    # Add the current year to make the date complete for parsing
                    today = datetime.now().date()
                    parsed = parsed.replace(year=today.year)
                    if parsed.tzinfo is None:
                         parsed = parsed.replace(tzinfo=tzlocal())
                    return parsed
                except ValueError:
                    pass # If explicit parsing fails, fall through to general parsing

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
            # dateutil_parser.parse is quite robust and can handle many formats, including
            # the Syslog format without a year by assuming the current year.
            try:
                parsed = dateutil_parser.parse(timestamp_str, fuzzy=True)
                if parsed.tzinfo is None:
                    # Assume local timezone if no timezone info is present
                    parsed = parsed.replace(tzinfo=tzlocal())
                return parsed
            except (ValueError, TypeError, OverflowError):
                return None # Return None if parsing fails

        except (ValueError, TypeError, OverflowError):
            # Catch potential errors during parsing from the initial type-specific attempts
            return None # Return None if parsing fails


    def parse_log_line(self, line: str) -> Tuple[Optional[datetime], str, Optional[str]]:
        """
        Parse a single log line to extract timestamp, original line, and timestamp type.

        Args:
            line: The log line string.

        Returns:
            Tuple containing:
            - Optional[datetime]: The parsed datetime object, or None.
            - str: The original log line (stripped).
            - Optional[str]: The identified timestamp type, or None.
        """
        timestamp_str, message, _, timestamp_type = self.extract_timestamp_from_line(line)

        if timestamp_str:
            timestamp = self.parse_timestamp_string(timestamp_str, timestamp_type)
            # Return the parsed timestamp (datetime object), the original line, and the timestamp type
            return timestamp, line.strip(), timestamp_type
        else:
            # No timestamp found or parsing failed during extraction
            return None, line.strip(), None # Return None for timestamp and type, and the original line


# Removed the parse_log_entries function as parsing is now integrated into the main loop
# def parse_log_entries(...): ...

def filter_log_entries_by_date(parsed_entry, start_date_str, end_date_str):
    """
    Filters a single parsed log entry by a specified date range.

    Args:
        parsed_entry: A single tuple (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted).
        start_date_str: Start date string (YYYY-MM-DD).
        end_date_str: End date string (YYYY-MM-DD).

    Returns:
        The parsed_entry tuple if it falls within the date range, otherwise None.
    """
    # Convert start and end date strings to datetime objects once
    # This conversion should ideally happen outside this function for efficiency
    # but kept here for self-containment based on the previous function structure.
    try:
        start_date = dateutil_parser.parse(start_date_str).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = dateutil_parser.parse(end_date_str).replace(hour=23, minute=59, second=59, microsecond=999999)
        date_filter_valid = True
    except (ValueError, TypeError):
        print("Error: Invalid start or end date format provided. Please use YYYY-MM-DD.")
        # If dates are invalid, no filtering can occur, so we'll indicate this.
        return parsed_entry # Or None, depending on desired behavior for invalid dates. Let's return entry for now.

    if not date_filter_valid:
        return parsed_entry # If dates were invalid, return the original entry

    file_path, iso_timestamp, original_line, timestamp_type, was_converted = parsed_entry

    if iso_timestamp:
        try:
            # Convert the ISO 8601 timestamp string back to a datetime object for comparison
            entry_timestamp = dateutil_parser.isoparse(iso_timestamp)

            # Ensure timezone awareness for comparison if needed (assuming timestamps are timezone aware)
            # If timestamps from logs might be naive, a more robust approach might be needed
            # For now, comparing timezone-aware datetimes directly is generally safe
            start_date_aware = start_date.replace(tzinfo=tzlocal())
            end_date_aware = end_date.replace(tzinfo=tzlocal())

            if start_date_aware <= entry_timestamp <= end_date_aware:
                return parsed_entry # Return the entry if it's within the date range
        except (ValueError, TypeError):
            # Handle cases where the ISO timestamp string itself is invalid after parsing
            print(f"Warning: Could not parse ISO timestamp for filtering: {iso_timestamp}. Skipping entry.")
            return None # Skip entry if its ISO timestamp is invalid for comparison
    else:
        # Entries with no timestamp are excluded from date filtering.
        return None # Skip entries with no timestamp

    return None # Return None if the entry does not meet the filter criteria


def sort_log_entries_by_timestamp(log_entries):
    """
    Sorts log entries by their ISO 8601 timestamps. Entries without timestamps
    are placed at the beginning.

    Args:
        log_entries: List of (file_path, iso_timestamp_string, original_log_line, timestamp_type, was_converted) tuples.

    Returns:
        List of sorted log entries.
    """
    # Sort the log entries by timestamp (the second element in the tuple)
    # If a timestamp is None, use datetime.min with local timezone to ensure it's placed first.
    # dateutil_parser.isoparse is used to convert the ISO 8601 string to a datetime object for sorting.
    return sorted(log_entries, key=lambda x: dateutil_parser.isoparse(x[1]) if x[1] else datetime.min.replace(tzinfo=tzlocal()))

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
    if output_dir and not os.path.exists(output_dir): # Check if output_dir is not an empty string and if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

    # Write the data to the CSV file
    try:
        with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)

            # Write the header row
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
    # 1. Set up argument parser
    arg_parser = argparse.ArgumentParser(description='Recursively search log files, filter by date, and output to CSV.')
    arg_parser.add_argument('-d', '--directory', required=True, help='Directory path to search for log files.')
    arg_parser.add_argument('-s', '--start_date', required=True, help='Start date for filtering (YYYY-MM-DD).')
    arg_parser.add_argument('-e', '--end_date', required=True, help='End date for filtering (YYYY-MM-DD).')
    # Optional arguments for output filenames with default values
    arg_parser.add_argument('--unfiltered_output', default='unfiltered_log_entries.csv', help='Filename for unfiltered output CSV (default: unfiltered_log_entries.csv).')
    arg_parser.add_argument('--filtered_output', default='filtered_log_entries.csv', help='Filename for filtered output CSV (default: filtered_log_entries.csv).')

    # 2. Parse command-line arguments
    args = arg_parser.parse_args()

    # Get inputs from parsed arguments
    directory_path = args.directory
    start_date_str = args.start_date
    end_date_str = args.end_date
    unfiltered_output_filename = args.unfiltered_output
    filtered_output_filename = args.filtered_output

    # Pre-parse start and end dates for filtering efficiency
    try:
        start_date_filter = dateutil_parser.parse(start_date_str).replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=tzlocal())
        end_date_filter = dateutil_parser.parse(end_date_str).replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=tzlocal())
        date_filter_valid_main = True
    except (ValueError, TypeError):
        print("Error: Invalid start or end date format provided via command line. Please use YYYY-MM-DD.")
        date_filter_valid_main = False
        # Decide how to proceed if dates are invalid - exit or process without filtering?
        # Let's exit for now if required date arguments are invalid.
        exit(1)


    # 3. Find all files (potential log files) recursively in the specified directory
    log_files = []
    # Walk through the directory and its subdirectories
    for root, _, files in tqdm(os.walk(directory_path), desc="Finding log files", unit="directory"): # Add tqdm here
        for file in files:
            file_path = os.path.join(root, file)
            # Check if the path is actually a file (and not a directory or symlink)
            if os.path.isfile(file_path):
                log_files.append(file_path)

    print(f"\nFound {len(log_files)} potential log files.")

    # 4. Process, parse, and filter log entries file by file to reduce memory usage
    parsed_log_entries_unfiltered = [] # Temporarily store unfiltered parsed entries for saving
    filtered_log_entries = [] # Store filtered entries in memory for sorting

    parser_instance = LogTimestampParser() # Create parser instance once

    unfiltered_csv_header = ["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"]
    filtered_csv_header = ["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"]


    # Open the unfiltered CSV file for writing before processing starts
    unfiltered_output_path = unfiltered_output_filename
    unfiltered_file = None
    unfiltered_writer = None

    try:
        unfiltered_file = open(unfiltered_output_path, 'w', newline='', encoding='utf-8')
        unfiltered_writer = csv.writer(unfiltered_file)
        unfiltered_writer.writerow(unfiltered_csv_header) # Write header to unfiltered file

        # Use tqdm for a progress bar while reading and processing files
        for file_path in tqdm(log_files, desc="Processing files", unit="file"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        # Parse each line
                        timestamp, original_line, timestamp_type = parser_instance.parse_log_line(line.strip())

                        was_converted = False
                        if timestamp_type and timestamp_type != 'ISO 8601':
                            was_converted = True

                        iso_timestamp = None
                        if timestamp:
                            # Convert to ISO 8601 format with microsecond precision
                            iso_timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                            # Ensure timezone offset is correctly formatted (e.g., +00:00 instead of +0000)
                            if iso_timestamp.endswith('00') and (iso_timestamp[-5] == '+' or iso_timestamp[-5] == '-'):
                                iso_timestamp = iso_timestamp[:-2] + ':' + iso_timestamp[-2:]

                        # Create a tuple for the parsed entry
                        parsed_entry = (file_path, iso_timestamp, original_line, timestamp_type, was_converted)

                        # Write the parsed entry to the unfiltered CSV immediately
                        unfiltered_writer.writerow(parsed_entry)

                        # Filter the entry by date and collect in memory if it passes the filter
                        if iso_timestamp and date_filter_valid_main: # Only filter if timestamp exists and dates are valid
                            try:
                                entry_timestamp = dateutil_parser.isoparse(iso_timestamp)
                                start_date_aware = start_date_filter
                                end_date_aware = end_date_filter

                                if start_date_aware <= entry_timestamp <= end_date_aware:
                                    filtered_log_entries.append(parsed_entry)
                            except (ValueError, TypeError):
                                # Handle cases where the ISO timestamp string itself is invalid after parsing
                                print(f"Warning: Could not parse ISO timestamp for filtering: {iso_timestamp}. Skipping entry from filtered output.")
                                pass
            except IOError as e:
                print(f"Error reading file {file_path}: {e}")
            except UnicodeDecodeError:
                 print(f"Warning: Could not decode file {file_path} with utf-8. Skipping.")

    except IOError as e:
        print(f"Error opening unfiltered output file {unfiltered_output_path}: {e}")
    finally:
        if unfiltered_file:
            unfiltered_file.close()


    print(f"\nProcessed and saved unfiltered entries to '{unfiltered_output_filename}'")
    print(f"Collected {len(filtered_log_entries)} entries for filtering.")


    # 5. Sort the filtered log entries
    print("\nSorting filtered log entries...")
    sorted_filtered_log_entries = sort_log_entries_by_timestamp(filtered_log_entries)
    print(f"Sorted {len(sorted_filtered_log_entries)} filtered log entries.")

    # 6. Save the filtered and sorted log entries to a separate CSV file
    filtered_output_path = filtered_output_filename
    save_log_entries_to_csv(sorted_filtered_log_entries, filtered_output_path)

    print("\nLog processing complete.")
