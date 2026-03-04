"""
log_processor.py (Refactored + Decompression Support)

Improved version with transparent decompression support for .gz, .zip, .bz2,
.tar.gz, .tar.bz2, .tar.xz, .xz, and plain text files — detected by magic
bytes, not just file extension.
"""

import os
import re
import csv
import gzip
import bz2
import lzma
import zipfile
import tarfile
import io
import argparse
from datetime import datetime
from dateutil import parser as dateutil_parser
from dateutil.tz import tzlocal, tzutc
from typing import Optional, Tuple, Iterator
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Magic byte signatures for format detection
# ---------------------------------------------------------------------------
MAGIC_BYTES = {
    b'\x1f\x8b':           'gzip',       # .gz / .tar.gz / .tgz
    b'BZh':                'bzip2',      # .bz2 / .tar.bz2
    b'\xfd7zXZ\x00':       'xz',         # .xz / .tar.xz
    b'PK\x03\x04':         'zip',        # .zip
    b'PK\x05\x06':         'zip',        # .zip (empty)
    b'PK\x07\x08':         'zip',        # .zip (spanned)
}

MAGIC_MAX_BYTES = 8  # only need to read this many bytes to identify format


def detect_compression(file_path: str) -> str:
    """
    Detect file compression type by reading magic bytes.
    Returns: 'gzip', 'bzip2', 'xz', 'zip', 'tar', or 'plain'
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(MAGIC_MAX_BYTES)

        for magic, fmt in MAGIC_BYTES.items():
            if header[:len(magic)] == magic:
                # Distinguish tar.gz / tar.bz2 / tar.xz from single-file compressed
                if fmt in ('gzip', 'bzip2', 'xz'):
                    if tarfile.is_tarfile(file_path):
                        return 'tar'
                return fmt

    except (IOError, OSError):
        pass

    return 'plain'


def iter_lines_from_file(file_path: str) -> Iterator[str]:
    """
    Transparently decompress (if needed) and yield decoded lines from a file.
    Handles: gzip, bzip2, xz, zip, tar.gz, tar.bz2, tar.xz, and plain text.
    Skips binary/non-text members inside archives.
    """
    fmt = detect_compression(file_path)

    try:
        # --- TAR ARCHIVES (.tar.gz, .tar.bz2, .tar.xz) ---
        if fmt == 'tar':
            with tarfile.open(file_path, 'r:*') as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    yield from _decode_stream(f, source=f"{file_path}::{member.name}")

        # --- GZIP (.gz) ---
        elif fmt == 'gzip':
            with gzip.open(file_path, 'rb') as f:
                yield from _decode_stream(f, source=file_path)

        # --- BZIP2 (.bz2) ---
        elif fmt == 'bzip2':
            with bz2.open(file_path, 'rb') as f:
                yield from _decode_stream(f, source=file_path)

        # --- XZ / LZMA (.xz) ---
        elif fmt == 'xz':
            with lzma.open(file_path, 'rb') as f:
                yield from _decode_stream(f, source=file_path)

        # --- ZIP (.zip) ---
        elif fmt == 'zip':
            with zipfile.ZipFile(file_path, 'r') as zf:
                for name in zf.namelist():
                    info = zf.getinfo(name)
                    if info.is_dir():
                        continue
                    with zf.open(name) as f:
                        yield from _decode_stream(f, source=f"{file_path}::{name}")

        # --- PLAIN TEXT ---
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                yield from f

    except (OSError, IOError, tarfile.TarError, zipfile.BadZipFile, EOFError, lzma.LZMAError) as e:
        print(f"  [WARN] Could not read {file_path}: {e}")


def _decode_stream(stream, source: str = '') -> Iterator[str]:
    """
    Read a binary stream line-by-line, trying UTF-8 then latin-1 fallback.
    Skips files that appear to be binary (null bytes in first 512 bytes).
    """
    try:
        raw_start = stream.read(512)
        if b'\x00' in raw_start:
            # Likely a binary file — skip it
            return
        # Re-combine and wrap in a text stream
        remainder = stream.read()
        full = raw_start + remainder
        text = full.decode('utf-8', errors='replace')
        for line in text.splitlines():
            yield line
    except Exception as e:
        print(f"  [WARN] Could not decode stream {source}: {e}")


# ---------------------------------------------------------------------------
# Timestamp parsing (unchanged from original)
# ---------------------------------------------------------------------------

class LogTimestampParser:
    """
    Parses various timestamp formats from log lines.
    """
    def __init__(self):
        self.timestamp_patterns = [
            (re.compile(r'([A-Za-z]{3},\s+\d{2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'), 'RFC 1123/822'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))'), 'ISO 8601'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:\s*[+-]\d{2}:?\d{2})?)'), 'ISO 8601 (space variant)'),
            (re.compile(r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'), 'Apache/Nginx'),
            (re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?:\s|$|\D)'), 'Syslog (Month Day Time)'),
            (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:\s|$|\D)'), 'Syslog (YYYY-MM-DD Time)'),
            (re.compile(r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))'), 'Windows Event Log'),
            (re.compile(r'(\d{8}\s+\d{2}:\d{2}:\d{2})'), 'YYYYMMDD Time'),
            (re.compile(r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})'), 'DD-MM-YYYY Time'),
            (re.compile(r'(\b\d{10}(?:\.\d{1,6})?\b)'), 'Unix Timestamp'),
            (re.compile(r'(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)'), 'Time Only'),
        ]

    def _validate_unix_timestamp(self, timestamp_str: str) -> bool:
        try:
            ts = float(timestamp_str)
            return 0 <= ts <= 4102444800
        except (ValueError, OverflowError):
            return False

    def extract_timestamp_from_line(self, line: str) -> Tuple[Optional[str], str, int, Optional[str]]:
        line = line.strip()
        if not line:
            return None, line, -1, None

        for pattern, pattern_type in self.timestamp_patterns:
            match = pattern.search(line)
            if match:
                timestamp_str = match.group(1).strip()
                if pattern_type == 'Unix Timestamp':
                    if not self._validate_unix_timestamp(timestamp_str):
                        continue
                start_pos = match.start(1)
                end_pos = match.end(1)
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
                    return parsed.replace(year=today.year, tzinfo=tzlocal())
                except ValueError:
                    pass
            elif timestamp_type == 'Time Only':
                try:
                    parsed = datetime.strptime(timestamp_str.strip(), '%H:%M:%S')
                    today = datetime.now().date()
                    return parsed.replace(year=today.year, month=today.month, day=today.day, tzinfo=tzlocal())
                except ValueError:
                    pass

            parsed = dateutil_parser.parse(timestamp_str, fuzzy=False)
            if parsed.year < 1970 or parsed.year > 2100:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=tzlocal())
            return parsed

        except Exception:
            return None

    def parse_log_line(self, line: str) -> Tuple[Optional[datetime], str, Optional[str]]:
        timestamp_str, message, _, timestamp_type = self.extract_timestamp_from_line(line)
        if timestamp_str:
            timestamp = self.parse_timestamp_string(timestamp_str, timestamp_type)
            return timestamp, line.strip(), timestamp_type
        return None, line.strip(), None


# ---------------------------------------------------------------------------
# Filtering / sorting / saving helpers
# ---------------------------------------------------------------------------

def filter_log_entries_by_date(iso_timestamp, start_date_filter, end_date_filter):
    if not iso_timestamp:
        return False
    try:
        entry_timestamp = dateutil_parser.isoparse(iso_timestamp)
        return start_date_filter <= entry_timestamp <= end_date_filter
    except (ValueError, TypeError):
        return False


def sort_log_entries_by_timestamp(log_entries):
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description='Recursively search log files (including compressed), filter by date, and output to CSV.'
    )
    arg_parser.add_argument('-d', '--directory', required=True, help='Directory path to search for log files.')
    arg_parser.add_argument('-s', '--start_date', required=True, help='Start date for filtering (YYYY-MM-DD).')
    arg_parser.add_argument('-e', '--end_date', required=True, help='End date for filtering (YYYY-MM-DD).')
    arg_parser.add_argument('--unfiltered_output', default='unfiltered_log_entries.csv', help='Filename for unfiltered output CSV.')
    arg_parser.add_argument('--filtered_output', default='filtered_log_entries.csv', help='Filename for filtered output CSV.')
    args = arg_parser.parse_args()

    try:
        start_date_filter = dateutil_parser.parse(args.start_date).replace(
            hour=0, minute=0, second=0, microsecond=0, tzinfo=tzutc())
        end_date_filter = dateutil_parser.parse(args.end_date).replace(
            hour=23, minute=59, second=59, microsecond=999999, tzinfo=tzutc())
    except (ValueError, TypeError):
        print("Error: Invalid date format. Please use YYYY-MM-DD.")
        exit(1)

    # Collect all files
    log_files = []
    for root, _, files in tqdm(os.walk(args.directory), desc="Finding log files", unit="directory"):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                log_files.append(file_path)

    print(f"Found {len(log_files)} files (will detect compression by content, not extension).")

    parser_instance = LogTimestampParser()
    filtered_log_entries = []

    try:
        with open(args.unfiltered_output, 'w', newline='', encoding='utf-8') as unfiltered_file:
            unfiltered_writer = csv.writer(unfiltered_file)
            unfiltered_writer.writerow(["Filename", "Timestamp (ISO 8601)", "Log Message", "Timestamp Type", "Was Converted"])

            for file_path in tqdm(log_files, desc="Processing files", unit="file"):
                compression = detect_compression(file_path)
                display_path = f"{file_path} [{compression}]"

                try:
                    for line in iter_lines_from_file(file_path):
                        timestamp, original_line, timestamp_type = parser_instance.parse_log_line(line)
                        was_converted = bool(timestamp_type and timestamp_type != 'ISO 8601')
                        iso_timestamp = timestamp.isoformat() if timestamp else None
                        parsed_entry = (display_path, iso_timestamp, original_line, timestamp_type, was_converted)
                        unfiltered_writer.writerow(parsed_entry)
                        if filter_log_entries_by_date(iso_timestamp, start_date_filter, end_date_filter):
                            filtered_log_entries.append(parsed_entry)

                except Exception as e:
                    print(f"Unexpected error processing {file_path}: {e}")

    except IOError as e:
        print(f"Error opening output file: {e}")
        exit(1)

    print(f"\nProcessed and saved unfiltered entries to '{args.unfiltered_output}'")
    print(f"Collected {len(filtered_log_entries)} entries within date range.")

    print("\nSorting filtered log entries...")
    sorted_filtered = sort_log_entries_by_timestamp(filtered_log_entries)
    save_log_entries_to_csv(sorted_filtered, args.filtered_output)
    print("\nLog processing complete.")
