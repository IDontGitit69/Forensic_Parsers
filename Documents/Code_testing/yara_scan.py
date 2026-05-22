#!/usr/bin/env python3
"""
YARA scanner with in-memory decompression for .gz/.tgz (via pigz) and .zip files.
Compressed files are never written to disk — decompressed bytes are scanned directly
in memory, which avoids temp-file I/O overhead.

Usage:
    python yara_scan.py --rules /etc/yara/rules/ --path /var/log/ --output ./results.json
    python yara_scan.py --rules mal.yar --path /var/log/syslog.gz --output ./results.json
    python yara_scan.py --rules mal.yar --path /var/log/archive.zip --output ./results.json
    python yara_scan.py --help

Dependencies:
    pip install yara-python
    apt install pigz   (or yum install pigz)
    zipfile + gzip are Python stdlib, no install needed
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import yara

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

PIGZ_EXTENSIONS = {".gz", ".tgz", ".pigz"}
ZIP_EXTENSIONS  = {".zip"}


# ---------------------------------------------------------------------------
# Decompression — returns raw bytes, nothing touches disk
# ---------------------------------------------------------------------------

def check_pigz():
    """Ensure pigz is available on PATH."""
    if shutil.which("pigz") is None:
        log.error("pigz not found. Install it with: apt install pigz  (or yum install pigz)")
        sys.exit(1)


def decompress_pigz_to_bytes(compressed_path: Path) -> bytes:
    """
    Stream a .gz/.tgz file through pigz and return the decompressed bytes.
    Nothing is written to disk.
    """
    log.info("  Decompressing in memory (pigz): %s", compressed_path.name)
    try:
        result = subprocess.run(
            ["pigz", "-d", "-c", str(compressed_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"pigz failed on {compressed_path}: {exc.stderr.decode().strip()}"
        ) from exc


def read_zip_entries_to_bytes(zip_path: Path) -> list:
    """
    Read all files inside a zip into memory.
    Returns a list of (entry_name, bytes) tuples.
    Skips directories and encrypted entries.
    """
    entries = []
    log.info("  Reading zip in memory: %s", zip_path.name)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    log.warning("  Skipping encrypted entry (no password support): %s", info.filename)
                    continue
                try:
                    data = zf.read(info.filename)
                    entries.append((info.filename, data))
                    log.info("    Read into memory: %s (%d bytes)", info.filename, len(data))
                except Exception as exc:
                    log.warning("    Could not read %s: %s", info.filename, exc)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Bad zip file {zip_path}: {exc}") from exc

    return entries


# ---------------------------------------------------------------------------
# YARA helpers
# ---------------------------------------------------------------------------

def load_rules(rules_path: str) -> yara.Rules:
    """Load YARA rules from a single .yar file or a directory of .yar/.yara files."""
    p = Path(rules_path)
    if p.is_file():
        log.info("Loading rules from file: %s", p)
        return yara.compile(filepath=str(p))
    elif p.is_dir():
        yar_files = sorted(p.rglob("*.yar")) + sorted(p.rglob("*.yara"))
        if not yar_files:
            log.error("No .yar/.yara files found in '%s'.", p)
            sys.exit(1)
        filepaths = {f.stem: str(f) for f in yar_files}
        log.info("Loading %d rule file(s) from: %s", len(filepaths), p)
        return yara.compile(filepaths=filepaths)
    else:
        log.error("Rules path '%s' is not a file or directory.", rules_path)
        sys.exit(1)


def scan_bytes(rules: yara.Rules, data: bytes, label: str):
    """
    Scan raw bytes with YARA. Returns a list of match dicts on success,
    or None if the scan could not be completed (corrupt data, I/O error, etc).
    """
    try:
        matches = rules.match(data=data, timeout=60)
        return _format_matches(matches)
    except yara.TimeoutError:
        log.warning("  YARA timed out scanning: %s", label)
    except yara.Error as exc:
        log.warning("  YARA error scanning %s: %s", label, exc)
    except (IOError, OSError) as exc:
        log.error("  I/O error scanning %s (corrupt file?): %s", label, exc)
    except Exception as exc:
        log.error("  Unexpected error scanning %s: %s", label, exc)
    return None


def scan_path(rules: yara.Rules, file_path: Path):
    """
    Scan a file on disk with YARA. Returns a list of match dicts on success,
    or None if the scan could not be completed (corrupt file, I/O error, etc).
    """
    try:
        matches = rules.match(str(file_path), timeout=60)
        return _format_matches(matches)
    except yara.TimeoutError:
        log.warning("  YARA timed out scanning: %s", file_path.name)
    except yara.Error as exc:
        log.warning("  YARA error scanning %s: %s", file_path.name, exc)
    except (IOError, OSError) as exc:
        log.error("  I/O error scanning %s (corrupt file?): %s", file_path.name, exc)
    except Exception as exc:
        log.error("  Unexpected error scanning %s: %s", file_path.name, exc)
    return None


def _format_matches(matches) -> list:
    """
    Convert yara match objects into serialisable dicts.
    Handles both yara-python API styles:
      - >= 4.3: match.strings is a list of StringMatch objects with .identifier / .instances
      - <  4.3: match.strings is a list of (offset, identifier, data) tuples
    """
    results = []
    for match in matches:
        hit = {
            "rule_name": match.rule,
            "rule_namespace": match.namespace,
            "tags": list(match.tags),
            "meta": match.meta,
            "matched_strings": [],
        }
        for string in match.strings:
            if isinstance(string, tuple):
                # Old API: (offset, identifier, data)
                offset, identifier, data = string
                hit["matched_strings"].append({
                    "identifier": identifier,
                    "instances": [{"offset": offset, "matched_data": data.hex()}],
                })
            else:
                # New API: StringMatch object with .identifier and .instances
                hit["matched_strings"].append({
                    "identifier": string.identifier,
                    "instances": [
                        {
                            "offset": instance.offset,
                            "matched_data": instance.matched_data.hex(),
                        }
                        for instance in string.instances
                    ],
                })
        results.append(hit)
    return results


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def collect_files(scan_path: Path) -> list:
    """
    Collect all files to scan from a path (file or directory).
    Skips any paths that raise I/O errors during traversal (e.g. corrupt
    disk images, bad sectors, broken mounts).
    """
    if scan_path.is_file():
        return [scan_path]
    elif scan_path.is_dir():
        files = []
        for f in scan_path.rglob("*"):
            try:
                if f.is_file():
                    files.append(f)
            except (OSError, IOError) as exc:
                log.warning("Skipping unreadable path during collection: %s — %s", f, exc)
        return files
    else:
        log.error("Scan path '%s' is not a file or directory.", scan_path)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Per-file dispatch
# ---------------------------------------------------------------------------

def process_file(rules, file_path, scan_results, files_scanned, files_skipped):
    """
    Dispatch a single file to the right handler based on extension.
    Compressed files are decompressed fully in memory before scanning.
    Returns updated (files_scanned, files_skipped).
    """
    suffix = file_path.suffix.lower()
    stat   = file_path.stat()

    def make_entry(original, label, compressed, ctype, matches, corrupt=False):
        return {
            "original_file":    str(original),
            "scanned_label":    label,
            "was_compressed":   compressed,
            "compression_type": ctype,
            "file_size_bytes":  stat.st_size,
            "scan_timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "corrupt":          corrupt,
            "match_count":      len(matches) if matches is not None else 0,
            "matches":          matches if matches is not None else [],
        }

    # --- ZIP (in-memory) ---
    if suffix in ZIP_EXTENSIONS:
        try:
            entries = read_zip_entries_to_bytes(file_path)
        except RuntimeError as exc:
            log.error("  Skipping zip — could not read: %s", exc)
            return files_scanned, files_skipped + 1

        if not entries:
            log.warning("  Zip had no scannable entries: %s", file_path.name)
            return files_scanned, files_skipped + 1

        for entry_name, data in entries:
            matches = scan_bytes(rules, data, entry_name)
            corrupt = matches is None
            files_scanned += 1
            entry = make_entry(file_path, f"{file_path.name}::{entry_name}", True, "zip", matches, corrupt)
            entry["zip_entry"] = entry_name
            scan_results.append(entry)
            _log_result(entry_name, matches)

        return files_scanned, files_skipped

    # --- PIGZ .gz/.tgz (in-memory) ---
    if suffix in PIGZ_EXTENSIONS:
        try:
            data = decompress_pigz_to_bytes(file_path)
        except RuntimeError as exc:
            log.error("  Skipping — pigz failed: %s", exc)
            return files_scanned, files_skipped + 1

        matches = scan_bytes(rules, data, file_path.name)
        corrupt = matches is None
        files_scanned += 1
        scan_results.append(make_entry(file_path, file_path.stem, True, "pigz", matches, corrupt))
        _log_result(file_path.name, matches)
        return files_scanned, files_skipped

    # --- Plain file (read from disk normally) ---
    matches = scan_path(rules, file_path)
    corrupt = matches is None
    files_scanned += 1
    scan_results.append(make_entry(file_path, file_path.name, False, None, matches, corrupt))
    _log_result(file_path.name, matches)
    return files_scanned, files_skipped


def _log_result(label, matches):
    if matches is None:
        log.error("  [%s] Skipped — could not be scanned (corrupt?).", label)
    elif matches:
        log.info("  [%s] WARNING %d match(es) found.", label, len(matches))
    else:
        log.info("  [%s] No matches.", label)


# ---------------------------------------------------------------------------
# Main scan routine
# ---------------------------------------------------------------------------

def run_scan(rules_path, scan_path, output_file):
    check_pigz()
    rules = load_rules(rules_path)

    all_files = collect_files(Path(scan_path))
    log.info("Found %d file(s) to process under '%s'.", len(all_files), scan_path)

    scan_results  = []
    files_scanned = 0
    files_skipped = 0

    for i, file_path in enumerate(sorted(all_files), start=1):
        log.info("[%d/%d] %s", i, len(all_files), file_path)
        files_scanned, files_skipped = process_file(
            rules, file_path, scan_results, files_scanned, files_skipped
        )

    total_matches  = sum(r["match_count"] for r in scan_results)
    files_corrupt  = sum(1 for r in scan_results if r.get("corrupt"))
    output = {
        "scan_metadata": {
            "scan_id":        f"yara-scan-{time.strftime('%Y%m%d-%H%M%S')}",
            "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rules_path":     str(rules_path),
            "scan_path":      str(scan_path),
            "files_scanned":  files_scanned,
            "files_skipped":  files_skipped,
            "files_corrupt":  files_corrupt,
            "total_matches":  total_matches,
        },
        "results": scan_results,
    }

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    log.info("Results written to: %s", out_path)
    log.info("Summary -- Scanned: %d | Skipped: %d | Corrupt: %d | Total YARA hits: %d",
             files_scanned, files_skipped, files_corrupt, total_matches)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="YARA scanner with in-memory decompression for .gz/.tgz and .zip files."
    )
    parser.add_argument("--rules",  required=True,
                        help="Path to a .yar rule file or directory of rule files")
    parser.add_argument("--path",   required=True,
                        help="File or directory to scan (supports .gz, .tgz, .zip, and plain files)")
    parser.add_argument("--output", required=True,
                        help="Path to write JSON results (e.g. ./results.json)")
    args = parser.parse_args()

    run_scan(
        rules_path=args.rules,
        scan_path=args.path,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
