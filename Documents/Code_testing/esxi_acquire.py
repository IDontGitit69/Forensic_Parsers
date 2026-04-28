#!/usr/bin/env python3
"""
esxi_acquire.py

Standalone ESXi log acquisition and conversion script.
Reads directly from a mounted forensic image or logical directory.
No KAPE required.

Usage:
    python3 esxi_acquire.py <source_mount_or_directory> <output_directory> [--hash]

Examples:
    python3 esxi_acquire.py /mnt/evidence /cases/output
    python3 esxi_acquire.py /mnt/evidence /cases/output --hash

The script will:
    1. Recursively walk the source looking for known ESXi log files
    2. Read them directly from the mounted media (no copy needed)
    3. Decompress any .gz files in memory via streaming
    4. Convert each log to a structured JSON file in the output directory

Each JSON record contains:
    Timestamp  - normalized ISO8601 e.g. 2025-05-24T05:28:37.128455Z
    TimeEpoch  - Unix epoch float with microsecond precision e.g. 1748064517.128455
    raw        - the full original log line

Performance notes:
    - Files are streamed line by line, not loaded fully into memory
    - JSON is written in compact format (no indentation) for speed and smaller output
    - MD5 hashing is opt-in via --hash flag (adds a full extra read per file)
    - Regex is compiled once at module level
    - Exact name matching uses a set for O(1) lookups
"""

import os
import sys
import gzip
import json
import re
import hashlib
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Exact base names - matched strictly to avoid partial prefix collisions
# e.g. "hostd" would match "hostd-probe" with a prefix check so we
# use exact matching here instead. Rotation variants (name.N) are also allowed.
# ---------------------------------------------------------------------------
EXACT_BASE_NAMES = frozenset([
    "hostd",
    "vmware",
    "envoy",       # envoy.log - distinct from envoy-access which is prefix matched
    "websso",      # websso.log - exact, websso_N.log.gz handled by prefix
])

# ---------------------------------------------------------------------------
# Exact extensionless filenames - files with no .log or .gz extension
# e.g. "messages", "messages.1"
# ---------------------------------------------------------------------------
EXACT_EXTENSIONLESS = frozenset([
    "messages",
])

# ---------------------------------------------------------------------------
# Prefix matches for unambiguous log names
# Stored as a tuple for fast iteration
# ---------------------------------------------------------------------------
KNOWN_LOG_PREFIXES = (
    "vpxa",
    "vmkernel",
    "auth",
    "shell",
    "vobd",
    "esxupdate",
    "vmksummary",
    "rhttproxy",
    "vmauthd",
    "envoy-access",   # envoy-access.log, envoy-access.N.gz
    "syslog",
    "vmkwarning",
    # vpxd- removed from here - handled by REGEX_PATTERNS below
    "websso_",        # websso_N.log.gz rotated variants
    "postgresql-",    # postgresql-Mon.log, postgresql-Mon.log-N.gz
)

# Compiled once at module level
TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?Z?)"
)

# Matches rotated exact-name variants e.g. hostd.0, vmware.3
ROTATION_PATTERN = re.compile(r"^(.+)\.\d+$")

# ---------------------------------------------------------------------------
# Regex patterns for logs where neither exact name nor simple prefix is
# precise enough. Each pattern is matched against the fully stripped basename.
# e.g. vpxd-12345 matches, vpxd-svcs-access and vpxd-profiler-12345 do not.
# ---------------------------------------------------------------------------
REGEX_PATTERNS = [
    re.compile(r"^vpxd-\d+$"),   # vpxd-12345.log, vpxd-12345.log.gz only
]


# ---------------------------------------------------------------------------
# File identification
# ---------------------------------------------------------------------------

def strip_log_extension(name: str) -> str:
    """Strip the outermost .log or .gz extension."""
    if name.endswith(".gz") or name.endswith(".log"):
        return name.rsplit(".", 1)[0]
    return name


def strip_all_log_extensions(name: str) -> str:
    """
    Fully strip all known log extensions for deep pattern matching.
    Handles double extensions like postgresql-Mon.log-1.gz -> postgresql-Mon
    and vpxd-1.log.gz -> vpxd-1
    """
    for _ in range(3):  # max 3 passes covers any double extension
        if name.endswith(".gz") or name.endswith(".log"):
            name = name.rsplit(".", 1)[0]
        else:
            break
    return name


def is_esxi_log(filename: str) -> bool:
    """
    Return True if filename matches a known ESXi log.
    Handles:
      - .log and .gz extensions (standard)
      - extensionless files like messages, messages.1
      - double extensions like postgresql-Mon.log-1.gz
    Uses frozenset O(1) lookup for exact names, tuple iteration for prefixes.
    """
    base = filename.lower()
    has_log_ext = base.endswith(".log") or base.endswith(".gz")

    # --- Extensionless files e.g. messages, messages.1, messages.1.gz ---
    if not has_log_ext:
        if base in EXACT_EXTENSIONLESS:
            return True
        # Rotated extensionless e.g. messages.1
        m = ROTATION_PATTERN.match(base)
        if m and m.group(1) in EXACT_EXTENSIONLESS:
            return True
        return False

    # --- Compressed extensionless e.g. messages.1.gz ---
    # After stripping .gz we may get messages.1 which has no .log ext
    if base.endswith(".gz"):
        inner = base[:-3]  # strip .gz
        if inner in EXACT_EXTENSIONLESS:
            return True
        m = ROTATION_PATTERN.match(inner)
        if m and m.group(1) in EXACT_EXTENSIONLESS:
            return True

    # Strip all log extensions for matching (handles double extensions)
    stripped = strip_all_log_extensions(base)

    # Check exact names - also allow rotation variants e.g. hostd.0
    if stripped in EXACT_BASE_NAMES:
        return True

    # Check if it's a rotated variant of an exact name e.g. hostd.0 -> hostd
    m = ROTATION_PATTERN.match(stripped)
    if m and m.group(1) in EXACT_BASE_NAMES:
        return True

    # Prefix match for unambiguous names
    for prefix in KNOWN_LOG_PREFIXES:
        if stripped.startswith(prefix):
            return True

    # Regex match for names requiring precise numeric or format patterns
    for pattern in REGEX_PATTERNS:
        if pattern.match(stripped):
            return True

    return False


def walk_source(source: str):
    """
    Generator that yields matching ESXi log file paths.
    Using a generator avoids building the full file list in memory.
    Skips symlinks to prevent loops on Linux mounts.
    """
    for root, dirs, files in os.walk(source, followlinks=False):
        for fname in files:
            if is_esxi_log(fname):
                yield os.path.join(root, fname)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def parse_timestamp(line: str):
    """
    Extract and normalize timestamp from start of log line.
    Returns (timestamp_str, time_epoch) or (None, None).
    """
    m = TIMESTAMP_PATTERN.match(line)
    if not m:
        return None, None

    frac_digits = m.group(2)

    try:
        if frac_digits:
            frac_normalized = frac_digits.ljust(6, "0")[:6]
            base_part = m.group(1).split(".")[0]
            dt = datetime(
                int(base_part[0:4]),
                int(base_part[5:7]),
                int(base_part[8:10]),
                int(base_part[11:13]),
                int(base_part[14:16]),
                int(base_part[17:19]),
                int(frac_normalized),
                tzinfo=timezone.utc,
            )
        else:
            base_part = m.group(1).rstrip("Z")
            dt = datetime(
                int(base_part[0:4]),
                int(base_part[5:7]),
                int(base_part[8:10]),
                int(base_part[11:13]),
                int(base_part[14:16]),
                int(base_part[17:19]),
                tzinfo=timezone.utc,
            )
            frac_normalized = "000000"

        timestamp_str = (
            f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
            f".{frac_normalized}Z"
        )
        time_epoch = round(dt.timestamp(), 6)
        return timestamp_str, time_epoch

    except (ValueError, IndexError):
        return None, None


# ---------------------------------------------------------------------------
# Hashing (opt-in)
# ---------------------------------------------------------------------------

def hash_file(filepath: str) -> str:
    """MD5 hash of source file. Only called when --hash flag is set."""
    md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        return f"error:{e}"


# ---------------------------------------------------------------------------
# Output filename
# ---------------------------------------------------------------------------

def derive_output_filename(filepath: str) -> str:
    """
    Derive JSON output filename from source path.
    e.g. vpxa.0.gz -> vpxa.0.json, hostd.log -> hostd.json
    """
    basename = os.path.basename(filepath).lower()
    stripped = strip_log_extension(basename)
    return stripped + ".json"


# ---------------------------------------------------------------------------
# Core processing - streaming line by line
# ---------------------------------------------------------------------------

def process_log_file(filepath: str, dest_dir: str, do_hash: bool,
                     acquisition_log: list, seen_names: dict):
    """
    Stream a single log file, parse lines, write compact JSON output.
    Never loads the entire file into memory.
    """
    source_size = os.path.getsize(filepath)
    source_hash = hash_file(filepath) if do_hash else None

    output_filename = derive_output_filename(filepath)

    # Handle collisions from same-named logs in different dirs (e.g. vmware.log)
    if output_filename in seen_names:
        seen_names[output_filename] += 1
        base = output_filename.replace(".json", "")
        output_filename = f"{base}_{seen_names[output_filename]}.json"
    else:
        seen_names[output_filename] = 0

    output_path = os.path.join(dest_dir, output_filename)
    record_count = 0

    try:
        # Open source - streaming, never fully in memory
        if filepath.endswith(".gz"):
            src = gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
        else:
            src = open(filepath, "r", encoding="utf-8", errors="replace")

        with src, open(output_path, "w", encoding="utf-8") as dst:
            dst.write("[\n")
            first = True
            for line in src:
                line = line.rstrip("\n")
                if not line.strip():
                    continue

                timestamp_str, time_epoch = parse_timestamp(line)
                record = {
                    "Timestamp": timestamp_str,
                    "TimeEpoch": time_epoch,
                    "raw": line,
                }

                # Compact JSON - no indent, separators tightened
                if not first:
                    dst.write(",\n")
                dst.write(json.dumps(record, separators=(",", ":")))
                first = False
                record_count += 1

            dst.write("\n]")

        print(f"  [+] {os.path.basename(filepath)} -> {record_count} records -> {output_filename}")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": record_count,
            "output_file": output_path,
            "status": "ok",
        })

    except PermissionError:
        print(f"  [!] Permission denied: {filepath}")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": 0,
            "output_file": None,
            "status": "error: permission denied",
        })
    except OSError as e:
        print(f"  [!] OS error on {filepath}: {e}")
        acquisition_log.append({
            "source_path": filepath,
            "source_size_bytes": source_size,
            "source_md5": source_hash,
            "records_extracted": 0,
            "output_file": None,
            "status": f"error: {e}",
        })


# ---------------------------------------------------------------------------
# Acquisition log
# ---------------------------------------------------------------------------

def write_acquisition_log(acquisition_log: list, dest_dir: str, source: str):
    """Write JSON acquisition log for chain of custody documentation."""
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
            json.dump(summary, f, separators=(",", ":"))
        print(f"\n[+] Acquisition log -> {log_path}")
    except Exception as e:
        print(f"\n[!] Could not write acquisition log: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    do_hash = "--hash" in args
    args = [a for a in args if a != "--hash"]

    if len(args) != 2:
        print("Usage: python3 esxi_acquire.py <source> <output_directory> [--hash]")
        print("")
        print("  --hash   Compute MD5 hash of each source file (slower, useful for IR docs)")
        print("")
        print("Examples:")
        print("  python3 esxi_acquire.py /mnt/evidence /cases/output")
        print("  python3 esxi_acquire.py /mnt/evidence /cases/output --hash")
        sys.exit(1)

    source = args[0].rstrip("/")
    dest_dir = args[1].rstrip("/")

    if not os.path.exists(source):
        print(f"[!] Source does not exist: {source}")
        sys.exit(1)

    os.makedirs(dest_dir, exist_ok=True)

    print(f"[*] ESXi Log Acquisition")
    print(f"[*] Source  : {source}")
    print(f"[*] Output  : {dest_dir}")
    print(f"[*] Hashing : {'yes' if do_hash else 'no (use --hash to enable)'}")
    print(f"[*] Scanning...\n")

    acquisition_log = []
    seen_names = {}
    file_count = 0

    for filepath in walk_source(source):
        file_count += 1
        process_log_file(filepath, dest_dir, do_hash, acquisition_log, seen_names)

    if file_count == 0:
        print("[!] No ESXi log files found. Check your source path.")
        sys.exit(0)

    write_acquisition_log(acquisition_log, dest_dir, source)

    total_records = sum(e["records_extracted"] for e in acquisition_log)
    print(f"\n[+] Complete. {file_count} files, {total_records} total records.")
    print(f"[+] Output -> {dest_dir}")


if __name__ == "__main__":
    main()
