"""
ESXi_LogToJson.py
 
Called by KAPE module ESXi_LogProcessing.mkape
Usage: python ESXi_LogToJson.py <sourceDirectory> <destinationDirectory>
 
- Walks the KAPE output directory recursively
- Finds all .log and .gz files matching known ESXi log names
- Decompresses any .gz files in memory
- Parses each log line into structured fields (timestamp, host, process, message)
- Outputs one JSON file per log source to the destination directory
"""
 
import os
import sys
import gzip
import json
import re
from datetime import datetime
 
# ---------------------------------------------------------------------------
# Known ESXi log filename prefixes we care about
# This mirrors the FileMask entries in the .tkape target
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
 
# ---------------------------------------------------------------------------
# ESXi log line regex patterns
# ESXi logs generally follow one of two formats:
#
# Standard syslog format:
#   2024-01-15T12:34:56.789Z hostname process[pid]: message
#
# vmkernel format:
#   2024-01-15T12:34:56.789Z cpu0:12345)WARNING: message
# ---------------------------------------------------------------------------
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)
 
VMKERNEL_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+"
    r"(?P<cpu>cpu\d+:\d+)\)"
    r"(?P<severity>[A-Z]+)?:?\s*"
    r"(?P<message>.+)$"
)
 
# Fallback for lines that dont match either pattern
FALLBACK_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?)\s+(?P<message>.+)$"
)
 
 
def is_esxi_log(filename: str) -> bool:
    """Check if a filename matches one of our known ESXi log prefixes."""
    base = os.path.basename(filename).lower()
    # Strip extensions to get the base name for prefix matching
    # e.g. vpxa.0.gz -> vpxa, hostd.log -> hostd
    for prefix in KNOWN_LOG_PREFIXES:
        if base.startswith(prefix):
            return True
    return False
 
 
def read_log_file(filepath: str) -> list[str]:
    """
    Read a log file and return its lines as a list of strings.
    Handles both plain .log files and .gz compressed files.
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
 
 
def parse_line(line: str) -> dict:
    """
    Attempt to parse a single log line into structured fields.
    Tries each known pattern in order, falls back to raw line if none match.
    """
    if not line.strip():
        return None
 
    # Try standard syslog format
    m = SYSLOG_PATTERN.match(line)
    if m:
        return {
            "timestamp": m.group("timestamp"),
            "hostname": m.group("hostname"),
            "process": m.group("process"),
            "pid": m.group("pid"),
            "severity": None,
            "message": m.group("message"),
            "raw": line,
        }
 
    # Try vmkernel format
    m = VMKERNEL_PATTERN.match(line)
    if m:
        return {
            "timestamp": m.group("timestamp"),
            "hostname": None,
            "process": m.group("cpu"),
            "pid": None,
            "severity": m.group("severity"),
            "message": m.group("message"),
            "raw": line,
        }
 
    # Try basic timestamp fallback
    m = FALLBACK_PATTERN.match(line)
    if m:
        return {
            "timestamp": m.group("timestamp"),
            "hostname": None,
            "process": None,
            "pid": None,
            "severity": None,
            "message": m.group("message"),
            "raw": line,
        }
 
    # No pattern matched - store as unparsed
    return {
        "timestamp": None,
        "hostname": None,
        "process": None,
        "pid": None,
        "severity": None,
        "message": None,
        "raw": line,
    }
 
 
def derive_output_filename(filepath: str) -> str:
    """
    Derive a clean output JSON filename from the source log filepath.
    Strips all extensions and appends .json
    e.g. vpxa.0.gz -> vpxa.0.json
         hostd.log  -> hostd.json
    """
    basename = os.path.basename(filepath)
    # Strip known extensions
    for ext in [".gz", ".log"]:
        if basename.endswith(ext):
            basename = basename[: -len(ext)]
    return basename + ".json"
 
 
def process_log_file(filepath: str, dest_dir: str):
    """
    Full pipeline for a single log file:
    1. Read and decompress if needed
    2. Parse each line
    3. Write structured JSON to destination
    """
    print(f"  [*] Processing: {filepath}")
    lines = read_log_file(filepath)
 
    if not lines:
        print(f"  [-] No content found in {filepath}, skipping.")
        return
 
    records = []
    for line in lines:
        parsed = parse_line(line)
        if parsed is not None:
            # Add source file metadata to each record for traceability
            parsed["source_file"] = os.path.basename(filepath)
            parsed["source_path"] = filepath
            records.append(parsed)
 
    if not records:
        print(f"  [-] No parseable records in {filepath}, skipping.")
        return
 
    output_filename = derive_output_filename(filepath)
    output_path = os.path.join(dest_dir, output_filename)
 
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, default=str)
        print(f"  [+] Written {len(records)} records -> {output_path}")
    except Exception as e:
        print(f"  [!] Failed to write {output_path}: {e}")
 
 
def walk_source(source_dir: str) -> list[str]:
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
 
    # Validate source
    if not os.path.isdir(source_dir):
        print(f"[!] Source directory does not exist: {source_dir}")
        sys.exit(1)
 
    # Create destination if it doesnt exist
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
