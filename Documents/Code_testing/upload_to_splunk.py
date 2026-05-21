#!/usr/bin/env python3
"""
Upload JSON files from a directory to Splunk via HTTP Event Collector (HEC).

Usage:
    python upload_to_splunk.py --dir ./logs --url https://splunk:8088 --token abc123 --index main
    python upload_to_splunk.py --help
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import requests
import urllib3

# Suppress SSL warnings when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def build_hec_event(data: dict | list, index: str, sourcetype: str, source: str) -> dict:
    """Wrap a JSON payload in the Splunk HEC event envelope."""
    return {
        "time": time.time(),
        "index": index,
        "sourcetype": sourcetype,
        "source": source,
        "event": data,
    }


def send_event(
    session: requests.Session,
    hec_url: str,
    event: dict,
    verify_ssl: bool,
    retries: int = 3,
    backoff: float = 2.0,
) -> bool:
    """POST a single HEC event with basic retry logic. Returns True on success."""
    endpoint = hec_url.rstrip("/") + "/services/collector/event"
    for attempt in range(1, retries + 1):
        try:
            resp = session.post(endpoint, json=event, verify=verify_ssl, timeout=30)
            if resp.status_code == 200:
                return True
            log.warning(
                "HEC returned %s on attempt %d/%d: %s",
                resp.status_code, attempt, retries, resp.text,
            )
        except requests.RequestException as exc:
            log.warning("Request error on attempt %d/%d: %s", attempt, retries, exc)

        if attempt < retries:
            time.sleep(backoff * attempt)

    return False


def upload_directory(
    directory: str,
    hec_url: str,
    hec_token: str,
    index: str,
    sourcetype: str = "_json",
    verify_ssl: bool = False,
    batch_size: int = 50,
    dry_run: bool = False,
) -> tuple[int, int]:
    """
    Walk *directory* and upload every .json file to Splunk HEC.

    Returns (files_ok, files_failed).
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        log.error("'%s' is not a directory or does not exist.", directory)
        sys.exit(1)

    json_files = sorted(dir_path.rglob("*.json"))
    if not json_files:
        log.warning("No .json files found in '%s'.", directory)
        return 0, 0

    log.info("Found %d JSON file(s) in '%s'.", len(json_files), directory)

    session = requests.Session()
    session.headers.update({"Authorization": f"Splunk {hec_token}"})

    ok_count = 0
    fail_count = 0

    for i, json_file in enumerate(json_files, start=1):
        log.info("[%d/%d] Processing: %s", i, len(json_files), json_file.name)

        # --- Parse file ---
        try:
            text = json_file.read_text(encoding="utf-8")
            payload = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            log.error("  Skipping — could not read/parse: %s", exc)
            fail_count += 1
            continue

        # Support files that are a JSON array (each element → its own event)
        records = payload if isinstance(payload, list) else [payload]

        if dry_run:
            log.info("  [DRY RUN] Would send %d event(s).", len(records))
            ok_count += 1
            continue

        # --- Send events (in batches) ---
        file_ok = True
        for chunk_start in range(0, len(records), batch_size):
            chunk = records[chunk_start : chunk_start + batch_size]
            for record in chunk:
                event = build_hec_event(
                    data=record,
                    index=index,
                    sourcetype=sourcetype,
                    source=str(json_file),
                )
                if not send_event(session, hec_url, event, verify_ssl):
                    log.error("  Failed to send an event from %s.", json_file.name)
                    file_ok = False

        if file_ok:
            log.info("  ✓ Uploaded %d event(s).", len(records))
            ok_count += 1
        else:
            fail_count += 1

    return ok_count, fail_count


def main():
    parser = argparse.ArgumentParser(
        description="Upload JSON files from a directory to Splunk HEC."
    )
    parser.add_argument("--dir",       required=True,  help="Directory containing JSON files")
    parser.add_argument("--url",       required=True,  help="Splunk HEC base URL (e.g. https://splunk.example.com:8088)")
    parser.add_argument("--token",     required=True,  help="HEC token")
    parser.add_argument("--index",     required=True,  help="Target Splunk index")
    parser.add_argument("--sourcetype",default="_json",help="Sourcetype (default: _json)")
    parser.add_argument("--batch-size",type=int, default=50, metavar="N",
                        help="Events per batch when a file is a JSON array (default: 50)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable SSL certificate verification (default: True → always disabled per spec)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Parse files but do not send anything to Splunk")
    args = parser.parse_args()

    # verify_ssl is False by default as requested; flag keeps it consistent
    verify_ssl = not args.no_verify_ssl  # will be False unless you explicitly flip it

    ok, failed = upload_directory(
        directory=args.dir,
        hec_url=args.url,
        hec_token=args.token,
        index=args.index,
        sourcetype=args.sourcetype,
        verify_ssl=verify_ssl,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    log.info("Done. Files succeeded: %d | Failed: %d", ok, failed)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
