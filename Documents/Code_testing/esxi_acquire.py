#!/usr/bin/env python3
"""
esxi_acquire.py

Standalone ESXi log acquisition and conversion script.
Reads directly from a mounted forensic image or logical directory.
No KAPE required.

Usage:
    python3 esxi_acquire.py <source_mount_or_directory> <output_directory>

Examples:
    python3 esxi_acquire.py /mnt/evidence /cases/output
    python3 esxi_acquire.py /media/analyst/ESXi_Image /cases/output

The script will:
    1. Recursively walk the source looking for known ESXi log files
    2. Read them directly from the mounted media (no copy needed)
    3. Decompress any .gz files in memory
    4. Convert each log to a structured JSON file in the output directory

Each JSON record contains:
    Timestamp  - normalized ISO8601 e.g. 2025-05-24T05:28:37.128455Z
    TimeEpoch  - Unix epoch float with microsecond precision e.g. 1748064517.128455
    raw        - the full original log line
"""

import os
import sys
import gzip
import json
import re
import hashlib
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Exact base names for logs where a prefix match would be too broad
# e.g. "hostd" would also match "hostd-probe" so we match exactly instead
# The base name is the filename stripped of its .log or .gz extension
# e.g. hostd.log -> hostd, hostd.0.gz -> hostd
# ---------------------------------------------------------------------------
EXACT_BASE_NAMES = {
    "hostd",
    "vmware",
}

# ---------------------------------------------------------------------------
# Prefix matches for logs where no ambiguity exists
# ---------------------------------------------------------------------------
KNOWN_LOG_PREFIXES = [
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
    "syslog",
    "vmkwarning",
]

# Matches ISO8601 timestamp at the start of an ESXi log line
# Handles variable fractional seconds and optional Z suffix
TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?Z?)"
)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def parse_timestamp(line: str):
    """
    Extract and normalize the timestamp from the start of a log line.

    Returns:
        timestamp_str : ISO8601 string with microseconds and Z suffix, or None
        time_epoch    : float Unix epoch with microsecond precision, or None
    """
    m = TIMESTAMP_PATTERN.match(line)
    if not m:
        return None, None

    raw_ts = m.group(1)
    frac_digits = m.group(2)

    try:
        if frac_digits:
            frac_normalized = frac_digits.ljust(6, "0")[:6]
            base_part = raw_ts.split(".")[0]
            dt_str = f"{base_part}.{frac_normalized}"
            dt = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            base_part = raw_ts.rstrip("Z")
            dt = datetime.strptime(base_part, "%Y-%m-%dT%H:%M:%S")
            frac_normalized = "000000"

        dt = dt.replace(tzinfo=timezone.utc)
        timestamp_str = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac_normalized}Z"
        time_epoch = round(dt.timestamp(), 6)

        return timestamp_str, time_epoch

    except ValueError:
        return None, None


# ---------------------------------------------------------------------------
# File identification
# ---------------------------------------------------------------------------

def strip_extensions(filename: str) -> str:
    """
    Strip .log and .gz extensions to get the base name for matching.
    e.g. hostd.log -> hostd
         vpxa.0.gz -> vpxa.0
         hostd-probe.0.gz -> hostd-probe.0
    """
    for ext in [".gz", ".log"]:
        if filename.endswith(ext):
            filename = filename[: -len(ext)]
    return filename


def is_esxi_log(filename: str) -> bool:
    """
    Return True if the filename matches a known ESXi log.

    Two matching strategies:
    - EXACT_BASE_NAMES : stripped base must equal the name exactly or as base.N
                         e.g. hostd, hostd.0, hostd.1 all match
                         but hostd-probe and hostd-probe.0 do not
    - KNOWN_LOG_PREFIXES : standard prefix match for unambiguous log names
    """
    base = os.path.basename(filename).lower()

    if not (base.endswith(".log") or base.endswith(".gz")):
        return False

    stripped = strip_extensions(base)

    # Exact match - stripped name must equal exact base or base.N (rotation number)
    for exact in EXACT_BASE_NAMES:
        if stripped == exact:
            return True
        if re.match(r"^" + re.escape(exact) + r"\.\d+$", stripped):
            return True

    # Prefix match for unambiguous log names
    for prefix in KNOWN_LOG_PREFIXES:
        if stripped.startswith(prefix):
            return True

    return False


def walk_source(source: str) -> list:
    """
    Recursively walk the source directory and return all matching ESXi log files.
    Skips symlinks to avoid loops on Linux mounts.
    """
    matched = []
    for root, dirs, files in os.walk(source, followlinks=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            if is_esxi_log(fname):
                matched.append(fpath)
    return matched


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------

def read_log_file(filepath: str) -> list:
    """
    Read a log file directly from the mounted source.
    Handles both plain .log and .gz compressed files.
    Never writes to the source - all decompression is done in memory.
    """
    lines = []
    try:
        if filepath.endswith(".gz"):
            with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
    except PermissionError:
        print(f"  [!] Permission denied: {filepath} - skipping")
    except OSError as e:
        print(f"  [!] OS error reading {filepath}: {e} - skipping")
    except Exception as e:
        print(f"  [!] Unexpected error reading {filepath}: {e} - skipping")
    return [line.rstrip("\n") for line in lines]


# ---------------------------------------------------------------------------
# MD5 hash of source file for acquisition integrity
# ---------------------------------------------------------------------------

def hash_file(filepath: str) -> str:
    """
    Compute MD5 hash of a source file for acquisition logging.
    Reads in chunks to handle large files without loading into memory.
    """
    md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        return f"error: {e}"


# ---------------------------------------------------------------------------
# Output filename derivation
# ---------------------------------------------------------------------------

def derive_output_filename(filepath: str) -> str:
    """
    Derive a clean JSON output filename from the source path.
    Strips .gz and .log extensions and appends .json.
    Preserves the rotated log number if present.
    e.g. vpxa.0.gz  -> vpxa.0.json
         hostd.log  -> hostd.json
         syslog.1.gz -> syslog.1.json
    """
    basename = os.path.basename(filepath)
    for ext in [".gz", ".log"]:
        if basename.endswith(ext):
            basename = basename[: -len(ext)]
    return basename + ".json"


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------

def process_log_file(filepath: str, dest_dir: str, acquisition_log: list):
    """
    Process a single log file:
    1. Hash the source file for integrity
    2. Read directly from mounted media
    3. Parse each line into Timestamp / TimeEpoch / raw
    4. Write JSON to output directory
    """
    print(f"  [*] Acquiring: {filepath}")

    # Hash before reading for integrity record
    source_hash = hash_file(filepath)
    source_size = os.path.getsize(filepath)

    lines = read_log_file(filepath)

    if not lines:
        print(f"  [-] No content found, skipping.")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": 0,
            "output_file": None,
            "status": "skipped - no content",
        })
        return

    records = []
    for line in lines:
        if not line.strip():
            continue
        timestamp_str, time_epoch = parse_timestamp(line)
        records.append({
            "Timestamp": timestamp_str,
            "TimeEpoch": time_epoch,
            "raw": line,
        })

    if not records:
        print(f"  [-] No parseable records, skipping.")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": 0,
            "output_file": None,
            "status": "skipped - no parseable records",
        })
        return

    output_filename = derive_output_filename(filepath)
    output_path = os.path.join(dest_dir, output_filename)

    # Handle filename collisions - if two logs from different dirs have the same
    # name (e.g. multiple vmware.log from different VMs) append a counter
    counter = 1
    while os.path.exists(output_path):
        base = derive_output_filename(filepath).replace(".json", "")
        output_path = os.path.join(dest_dir, f"{base}_{counter}.json")
        counter += 1

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        print(f"  [+] {len(records)} records -> {output_path}")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": len(records),
            "output_file": output_path,
            "status": "ok",
        })
    except Exception as e:
        print(f"  [!] Failed to write {output_path}: {e}")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": 0,
            "output_file": None,
            "status": f"write error: {e}",
        })


# ---------------------------------------------------------------------------
# Acquisition log
# ---------------------------------------------------------------------------

def write_acquisition_log(acquisition_log: list, dest_dir: str, source: str):
    """
    Write a JSON acquisition log summarizing what was collected.
    Useful for chain of custody documentation.
    """
    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    summary = {
        "acquisition_time_utc": run_time,
        "source": source,
        "total_files_processed": len(acquisition_log),
        "total_records_extracted": sum(e["records_extracted"] for e in acquisition_log),
        "files": acquisition_log,
    }
    log_path = os.path.join(dest_dir, "acquisition_log.json")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[+] Acquisition log written -> {log_path}")
    except Exception as e:
        print(f"\n[!] Could not write acquisition log: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 esxi_acquire.py <source_mount_or_directory> <output_directory>")
        print("")
        print("Examples:")
        print("  python3 esxi_acquire.py /mnt/evidence /cases/output")
        print("  python3 esxi_acquire.py /media/analyst/ESXi_Image /cases/output")
        sys.exit(1)

    source = sys.argv[1].rstrip("/")
    dest_dir = sys.argv[2].rstrip("/")

    if not os.path.exists(source):
        print(f"[!] Source does not exist: {source}")
        sys.exit(1)

    os.makedirs(dest_dir, exist_ok=True)

    print(f"[*] ESXi Log Acquisition")
    print(f"[*] Source : {source}")
    print(f"[*] Output : {dest_dir}")
    print(f"[*] Scanning for ESXi logs...\n")

    matched_files = walk_source(source)

    if not matched_files:
        print("[!] No ESXi log files found. Check your source path.")
        sys.exit(0)

    print(f"[*] Found {len(matched_files)} log file(s).\n")

    acquisition_log = []
    for filepath in matched_files:
        process_log_file(filepath, dest_dir, acquisition_log)

    write_acquisition_log(acquisition_log, dest_dir, source)

    total_records = sum(e["records_extracted"] for e in acquisition_log)
    print(f"[+] Complete. {len(matched_files)} files processed, {total_records} total records extracted.")
    print(f"[+] Output -> {dest_dir}")


if __name__ == "__main__":
    main()
