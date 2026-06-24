#!/usr/bin/env python3
"""
thor_iris_forwarder.py — Listens for THOR Lite's JSON syslog output and
forwards each finding to DFIR-IRIS as an Alert.

Run THOR Lite with:
    sudo ./thor-lite-linux-64 -p /mnt/IOC_SCAN/ --customonly -a Filescan \
        -s 127.0.0.1:9999:JSON:UDP

...and run this script listening on the same port, configured with your
IRIS host + API key. Every Filescan finding becomes an IRIS alert:
  - If ANY of the rule's numbered reasons has sigtype "custom" (i.e. it came
    from our IOC-derived YARA bundle, not THOR's built-in signature base),
    the alert is filed as Critical severity, full stop — no score-based
    tiering. An analyst-confirmed IOC match should never be buried among
    routine findings.
  - Everything else (THOR's built-in signature/IOC hits) is mapped from
    THOR's own numeric `score` field into a sensible severity tier.

Confirmed against real output from a live THOR Lite v10.7.30 scan and a
live IRIS v2.4.27 instance — see thor_iris_forwarder.md for what was
actually verified vs. assumed.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("thor_iris_forwarder")


# ── IRIS severity IDs ─────────────────────────────────────────────────────────
# Confirmed by querying the live `severities` table on a real IRIS v2.4.27
# instance:
#   1=Medium  2=Unspecified  3=Informational  4=Low  5=High  6=Critical
SEVERITY_CRITICAL = 6
SEVERITY_HIGH = 5
SEVERITY_MEDIUM = 1
SEVERITY_LOW = 4
SEVERITY_INFO = 3

# IRIS alert status: confirmed from live `alert_status` table. 2 = "New".
STATUS_NEW = 2


def score_to_severity(score: int) -> int:
    """
    Map THOR's built-in-signature numeric score to an IRIS severity tier.
    These thresholds are a starting point, not derived from any official
    THOR documentation of scoring tiers -- tune them once you've seen real
    score distributions from your own scans. They only apply to NON-custom
    hits; custom IOC-derived hits always go Critical regardless of score
    (see is_custom_hit below).
    """
    if score >= 150:
        return SEVERITY_HIGH
    if score >= 75:
        return SEVERITY_MEDIUM
    if score >= 40:
        return SEVERITY_LOW
    return SEVERITY_INFO


@dataclass
class ThorReason:
    rulename: str = ""
    reason: str = ""
    subscore: int = 0
    sigtype: str = ""
    sigclass: str = ""
    author: str = ""


@dataclass
class ThorFinding:
    """A single parsed Filescan finding line from THOR's JSON syslog output."""
    time: str
    hostname: str
    level: str
    score: int
    file: str
    md5: str
    sha1: str
    sha256: str
    scanid: str
    reasons: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def is_custom_hit(self) -> bool:
        """True if ANY reason on this finding came from a custom (IOC-derived) rule."""
        return any(r.sigtype == "custom" for r in self.reasons)

    @property
    def severity_id(self) -> int:
        if self.is_custom_hit:
            return SEVERITY_CRITICAL
        return score_to_severity(self.score)


def parse_thor_json_line(line: str) -> Optional[ThorFinding]:
    """
    Parse one line of THOR's JSON syslog output. Returns None for any line
    that isn't an actual Filescan finding (startup/info/init noise, which
    makes up most of THOR's syslog traffic per real observed output).
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        log.warning(f"Could not parse line as JSON, skipping: {line[:200]}")
        return None

    # Only Filescan findings carry a 'file' + 'score' + numbered reason_N
    # fields. Confirmed from real output: every other message (Startup,
    # Init, Report, etc.) lacks these entirely.
    if data.get("module") != "Filescan" or "file" not in data or "score" not in data:
        return None

    # Walk the numbered reason_N / sigtype_N / rulename_N fields.
    # reasons_count tells us how many exist; confirmed real field name.
    reasons = []
    reasons_count = data.get("reasons_count", 0)
    for i in range(1, reasons_count + 1):
        reasons.append(
            ThorReason(
                rulename=data.get(f"rulename_{i}", ""),
                reason=data.get(f"reason_{i}", ""),
                subscore=data.get(f"subscore_{i}", 0),
                sigtype=data.get(f"sigtype_{i}", ""),
                sigclass=data.get(f"sigclass_{i}", ""),
                author=data.get(f"author_{i}", ""),
            )
        )

    return ThorFinding(
        time=data.get("time", ""),
        hostname=data.get("hostname", ""),
        level=data.get("level", ""),
        score=data.get("score", 0),
        file=data.get("file", ""),
        md5=data.get("md5", ""),
        sha1=data.get("sha1", ""),
        sha256=data.get("sha256", ""),
        scanid=data.get("scanid", ""),
        reasons=reasons,
        raw=data,
    )


# ── IRIS alert creation ───────────────────────────────────────────────────────

def build_alert_payload(finding: ThorFinding, customer_id: int) -> dict:
    """
    Build a POST /alerts/add payload from a parsed THOR finding.
    Field names and required set confirmed directly against a live IRIS
    v2.4.27 AlertSchema (see thor_iris_forwarder.md).
    """
    rule_summary = "; ".join(
        f"{r.rulename} (score {r.subscore}, {r.sigtype})" for r in finding.reasons
    ) or "unknown rule"

    title_prefix = "[IOC MATCH] " if finding.is_custom_hit else "[THOR] "
    title = f"{title_prefix}{finding.hostname}: {rule_summary}"
    if len(title) > 200:
        title = title[:197] + "..."

    description_lines = [
        f"THOR Lite finding on host {finding.hostname}.",
        f"File: {finding.file}",
        f"Total score: {finding.score}",
        "",
        "Matched rules:",
    ]
    for r in finding.reasons:
        description_lines.append(f"  - {r.rulename} [{r.sigtype}]: {r.reason}")

    return {
        "alert_title": title,
        "alert_description": "\n".join(description_lines),
        "alert_source": "THOR Lite",
        "alert_source_ref": finding.scanid,
        "alert_severity_id": finding.severity_id,
        "alert_status_id": STATUS_NEW,
        "alert_customer_id": customer_id,
        "alert_source_content": finding.raw,  # full original JSON for drill-down
        "alert_source_event_time": finding.time,
        "alert_tags": "thor-lite,ioc-match" if finding.is_custom_hit else "thor-lite",
    }


def send_alert(host: str, api_key: str, payload: dict) -> bool:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            f"{host.rstrip('/')}/alerts/add",
            headers=headers,
            json=payload,
            verify=False,
            timeout=10,
        )
    except requests.RequestException as e:
        log.error(f"Failed to reach IRIS: {e}")
        return False

    if resp.status_code not in (200, 201):
        log.error(f"IRIS rejected alert (status {resp.status_code}): {resp.text[:500]}")
        return False

    try:
        alert_id = resp.json().get("data", {}).get("alert_id")
    except Exception:
        alert_id = "?"
    log.info(f"Created IRIS alert #{alert_id}: {payload['alert_title']}")
    return True


# ── UDP listener ──────────────────────────────────────────────────────────────

def run_listener(bind_host: str, bind_port: int, iris_host: str, api_key: str,
                  customer_id: int, dry_run: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, bind_port))
    log.info(f"Listening for THOR JSON syslog on udp://{bind_host}:{bind_port}")
    log.info(f"Forwarding to IRIS at {iris_host} (customer_id={customer_id})"
              + (" [DRY RUN -- not actually sending]" if dry_run else ""))

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            line = data.decode("utf-8", errors="replace")
        except Exception as e:
            log.warning(f"Could not decode packet from {addr}: {e}")
            continue

        finding = parse_thor_json_line(line)
        if finding is None:
            continue  # not a Filescan finding, ignore (startup/info noise)

        log.info(
            f"Finding: {finding.file} (score={finding.score}, "
            f"custom={finding.is_custom_hit}, severity_id={finding.severity_id})"
        )

        payload = build_alert_payload(finding, customer_id)

        if dry_run:
            log.info(f"[DRY RUN] Would send alert: {json.dumps(payload, default=str)[:500]}")
            continue

        send_alert(iris_host, api_key, payload)


def main():
    parser = argparse.ArgumentParser(description="Forward THOR Lite JSON syslog findings to IRIS as alerts")
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--bind-port", type=int, default=9999)
    parser.add_argument("--iris-host", required=True, help="e.g. https://localhost:8443")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--customer-id", type=int, default=1,
                        help="IRIS client_id to attribute alerts to (default 1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and log findings but don't actually POST to IRIS")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        run_listener(
            bind_host=args.bind_host,
            bind_port=args.bind_port,
            iris_host=args.iris_host,
            api_key=args.api_key,
            customer_id=args.customer_id,
            dry_run=args.dry_run,
        )
    except KeyboardInterrupt:
        log.info("Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()