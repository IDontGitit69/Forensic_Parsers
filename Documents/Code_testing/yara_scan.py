#!/usr/bin/env python3
"""
YARA scanner with pigz and zip decompression support for compressed log files.

Usage:
    python yara_scan.py --rules /etc/yara/rules/ --path /var/log/ --output ./results.json
    python yara_scan.py --rules mal.yar --path /var/log/syslog.gz --output ./results.json
    python yara_scan.py --rules mal.yar --path /var/log/archive.zip --output ./results.json
    python yara_scan.py --help

Dependencies:
    pip install yara-python
    apt install pigz   (or yum install pigz)
    zipfile is part of Python stdlib, no install needed
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
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

# Extensions handled by pigz
PIGZ_EXTENSIONS = {".gz", ".tgz", ".pigz"}
# Extensions handled by Python's zipfile module
ZIP_EXTENSIONS = {".zip"}


# ---------------------------------------------------------------------------
# Decompression helpers
# ---------------------------------------------------------------------------

def check_pigz():
    """Ensure pigz is available on PATH."""
    if shutil.which("pigz") is None:
        log.error("pigz not found. Install it with: apt install pigz  (or yum install pigz)")
        sys.exit(1)


def decompress_with_pigz(compressed_path: Path, dest_dir: str) -> Path:
    """
    Decompress a .gz/.tgz file using pigz into dest_dir.
    Returns the path to the decompressed file.
    """
    stem = compressed_path.stem  # "syslog" from "syslog.gz"
    dest_path = Path(dest_dir) / stem

    log.info("  Decompressing with pigz: %s -> %s", compressed_path.name, dest_path.name)
    try:
        with open(dest_path, "wb") as out_f:
            subprocess.run(
                ["pigz", "-d", "-c", str(compressed_path)],
                stdout=out_f,
                stderr=subprocess.PIPE,
                check=True,
            )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"pigz failed on {compressed_path}: {exc.stderr.decode().strip()}"
        ) from exc

    return dest_path


def extract_zip(zip_path: Path, dest_dir: str) -> list:
    """
    Extract all files from a zip archive into dest_dir.
    Returns a list of Paths to the extracted files.
    Skips encrypted entries and directories.
    """
    extracted = []
    log.info("  Extracting zip: %s", zip_path.name)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue
                # Warn and skip encrypted entries
                if info.flag_bits & 0x1:
                    log.warning("  Skipping encrypted entry (no password support): %s", info.filename)
                    continue
                try:
                    out_path = zf.extract(info, path=dest_dir)
                    extracted.append(Path(out_path))
                    log.info("    Extracted: %s", info.filename)
                except Exception as exc:
                    log.warning("    Could not extract %s: %s", info.filename, exc)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Bad zip file {zip_path}: {exc}") from exc

    log.info("  %d file(s) extracted from %s", len(extracted), zip_path.name)
    return extracted


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


def scan_file(rules: yara.Rules, file_path: Path) -> list:
    """Scan a single file with YARA. Returns a list of match dicts."""
    try:
        matches = rules.match(str(file_path), timeout=60)
    except yara.TimeoutError:
        log.warning("  YARA timed out scanning: %s", file_path.name)
        return []
    except yara.Error as exc:
        log.warning("  YARA error scanning %s: %s", file_path.name, exc)
        return []

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
    """Collect all files to scan from a path (file or directory)."""
    if scan_path.is_file():
        return [scan_path]
    elif scan_path.is_dir():
        return [f for f in scan_path.rglob("*") if f.is_file()]
    else:
        log.error("Scan path '%s' is not a file or directory.", scan_path)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main scan routine
# ---------------------------------------------------------------------------

def process_file(rules, file_path, tmp_dir, scan_results, files_scanned, files_skipped):
    """
    Handle a single file: decompress if needed, scan with YARA, append results.
    Returns updated (files_scanned, files_skipped) counts.
    """
    suffix = file_path.suffix.lower()
    stat = file_path.stat()

    # --- ZIP ---
    if suffix in ZIP_EXTENSIONS:
        try:
            extracted_files = extract_zip(file_path, tmp_dir)
        except RuntimeError as exc:
            log.error("  Skipping zip — extraction failed: %s", exc)
            return files_scanned, files_skipped + 1

        if not extracted_files:
            log.warning("  Zip contained no scannable files: %s", file_path.name)
            return files_scanned, files_skipped + 1

        for extracted in extracted_files:
            matches = scan_file(rules, extracted)
            files_scanned += 1
            scan_results.append({
                "original_file": str(file_path),
                "zip_entry": extracted.name,
                "scanned_file": str(extracted),
                "was_compressed": True,
                "compression_type": "zip",
                "file_size_bytes": stat.st_size,
                "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "match_count": len(matches),
                "matches": matches,
            })
            if matches:
                log.info("  [%s] WARNING %d match(es) found.", extracted.name, len(matches))
            else:
                log.info("  [%s] No matches.", extracted.name)

        return files_scanned, files_skipped

    # --- PIGZ (.gz / .tgz) ---
    if suffix in PIGZ_EXTENSIONS:
        try:
            scan_target = decompress_with_pigz(file_path, tmp_dir)
        except RuntimeError as exc:
            log.error("  Skipping — pigz decompression failed: %s", exc)
            return files_scanned, files_skipped + 1

        matches = scan_file(rules, scan_target)
        files_scanned += 1
        scan_results.append({
            "original_file": str(file_path),
            "scanned_file": str(scan_target),
            "was_compressed": True,
            "compression_type": "pigz",
            "file_size_bytes": stat.st_size,
            "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "match_count": len(matches),
            "matches": matches,
        })
        if matches:
            log.info("  WARNING %d match(es) found.", len(matches))
        else:
            log.info("  No matches.")

        return files_scanned, files_skipped

    # --- Plain file ---
    matches = scan_file(rules, file_path)
    files_scanned += 1
    scan_results.append({
        "original_file": str(file_path),
        "scanned_file": str(file_path),
        "was_compressed": False,
        "compression_type": None,
        "file_size_bytes": stat.st_size,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "match_count": len(matches),
        "matches": matches,
    })
    if matches:
        log.info("  WARNING %d match(es) found.", len(matches))
    else:
        log.info("  No matches.")

    return files_scanned, files_skipped


def run_scan(rules_path, scan_path, output_file, keep_decompressed=False):
    check_pigz()
    rules = load_rules(rules_path)

    all_files = collect_files(Path(scan_path))
    log.info("Found %d file(s) to process under '%s'.", len(all_files), scan_path)

    scan_results = []
    files_scanned = 0
    files_skipped = 0

    tmp_dir = tempfile.mkdtemp(prefix="yara_scan_")
    log.info("Temp dir for decompressed files: %s", tmp_dir)

    try:
        for i, file_path in enumerate(sorted(all_files), start=1):
            log.info("[%d/%d] %s", i, len(all_files), file_path)
            files_scanned, files_skipped = process_file(
                rules, file_path, tmp_dir, scan_results, files_scanned, files_skipped
            )
    finally:
        if keep_decompressed:
            log.info("Decompressed/extracted files retained at: %s", tmp_dir)
        else:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            log.info("Temp files cleaned up.")

    total_matches = sum(r["match_count"] for r in scan_results)
    output = {
        "scan_metadata": {
            "scan_id": f"yara-scan-{time.strftime('%Y%m%d-%H%M%S')}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rules_path": str(rules_path),
            "scan_path": str(scan_path),
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "total_matches": total_matches,
        },
        "results": scan_results,
    }

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    log.info("Results written to: %s", out_path)
    log.info("Summary -- Scanned: %d | Skipped: %d | Total YARA hits: %d",
             files_scanned, files_skipped, total_matches)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="YARA scanner with pigz and zip decompression for compressed log files."
    )
    parser.add_argument("--rules",  required=True,
                        help="Path to a .yar rule file or directory of rule files")
    parser.add_argument("--path",   required=True,
                        help="File or directory to scan (supports .gz, .tgz, .zip)")
    parser.add_argument("--output", required=True,
                        help="Path to write JSON results (e.g. ./results.json)")
    parser.add_argument("--keep-decompressed", action="store_true",
                        help="Keep decompressed/extracted temp files after scan")
    args = parser.parse_args()

    run_scan(
        rules_path=args.rules,
        scan_path=args.path,
        output_file=args.output,
        keep_decompressed=args.keep_decompressed,
    )


if __name__ == "__main__":
    main()
