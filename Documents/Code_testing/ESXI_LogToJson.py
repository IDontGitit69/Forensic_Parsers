"""
ESXi_LogToJson.py

Called by KAPE module ESXi_LogProcessing.mkape
Usage: python ESXi_LogToJson.py <sourceDirectory> <destinationDirectory>

- Walks the KAPE output directory recursively
- Finds all .log and .gz files matching known ESXi log names
- Decompresses any .gz files in memory
- Outputs one JSON file per log source to the destination directory

Each record contains three fields:
    timestamp   - extracted from the start of the log line if present, else null
    raw         - the full original log line
    source_file - the filename the line came from
"""

import os
import sys
import gzip
import json
import re

# ---------------------------------------------------------------------------
# Known ESXi log filename prefixes - mirrors the .tkape FileMask entries
# ---------------------------------------------------------------------------
KNOWN_LOG_PREFIXES = [
    "hostd",
    "vpxa",
    "vmkernel",
    "auth",
    "shell",
    "vobd",
    "esxupdate",
    "vmksummary",
    "rhttproxy",
    "vmauthd",
    "envoy-access",
    "vmware",
]

# Matches the ISO8601-style timestamp ESXi puts at the start of every log line
# e.g. 2024-01-15T12:34:56.789Z
TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?)"
)


def is_esxi_log(filename: str) -> bool:
    """Check if a filename matches one of our known ESXi log prefixes."""
    base = os.path.basename(filename).lower()
    for prefix in KNOWN_LOG_PREFIXES:
        if base.startswith(prefix):
            return True
    return False


def read_log_file(filepath: str) -> list:
    """
    Read a log file and return its lines.
    Handles both plain .log and .gz compressed files.
    """
    lines = []
    try:
        if filepath.endswith(".gz"):
            with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
    except Exception as e:
        print(f"  [!] Could not read {filepath}: {e}")
    return [line.rstrip("\n") for line in lines]


def extract_timestamp(line: str):
    """
    Pull the timestamp from the beginning of a log line.
    Returns the timestamp string if found, None otherwise.
    """
    m = TIMESTAMP_PATTERN.match(line)
    if m:
        return m.group(1)
    return None


def derive_output_filename(filepath: str) -> str:
    """
    Derive a clean output JSON filename from the source log filepath.
    Strips .gz and .log extensions and appends .json
    e.g. vpxa.0.gz -> vpxa.0.json
         hostd.log  -> hostd.json
    """
    basename = os.path.basename(filepath)
    for ext in [".gz", ".log"]:
        if basename.endswith(ext):
            basename = basename[: -len(ext)]
    return basename + ".json"


def process_log_file(filepath: str, dest_dir: str):
    """
    Full pipeline for a single log file:
    1. Read and decompress if needed
    2. Extract timestamp from each line
    3. Write simplified JSON to destination
    """
    print(f"  [*] Processing: {filepath}")
    lines = read_log_file(filepath)

    if not lines:
        print(f"  [-] No content found in {filepath}, skipping.")
        return

    source_filename = os.path.basename(filepath)
    records = []

    for line in lines:
        if not line.strip():
            continue
        records.append({
            "timestamp": extract_timestamp(line),
            "raw": line,
            "source_file": source_filename,
        })

    if not records:
        print(f"  [-] No records found in {filepath}, skipping.")
        return

    output_filename = derive_output_filename(filepath)
    output_path = os.path.join(dest_dir, output_filename)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        print(f"  [+] Written {len(records)} records -> {output_path}")
    except Exception as e:
        print(f"  [!] Failed to write {output_path}: {e}")


def walk_source(source_dir: str) -> list:
    """
    Recursively walk the source directory and return all files
    that match known ESXi log prefixes with .log or .gz extensions.
    """
    matched = []
    for root, dirs, files in os.walk(source_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            lower = fname.lower()
            if (lower.endswith(".log") or lower.endswith(".gz")) and is_esxi_log(fname):
                matched.append(fpath)
    return matched


def main():
    if len(sys.argv) != 3:
        print("Usage: python ESXi_LogToJson.py <sourceDirectory> <destinationDirectory>")
        sys.exit(1)

    source_dir = sys.argv[1]
    dest_dir = sys.argv[2]

    if not os.path.isdir(source_dir):
        print(f"[!] Source directory does not exist: {source_dir}")
        sys.exit(1)

    os.makedirs(dest_dir, exist_ok=True)

    print(f"[*] ESXi Log Processor")
    print(f"[*] Source : {source_dir}")
    print(f"[*] Output : {dest_dir}")
    print(f"[*] Scanning for ESXi logs...")

    matched_files = walk_source(source_dir)

    if not matched_files:
        print("[!] No ESXi log files found in source directory. Check your KAPE target output.")
        sys.exit(0)

    print(f"[*] Found {len(matched_files)} log file(s) to process.\n")

    for filepath in matched_files:
        process_log_file(filepath, dest_dir)

    print(f"\n[+] Done. JSON files written to: {dest_dir}")


if __name__ == "__main__":
    main()
