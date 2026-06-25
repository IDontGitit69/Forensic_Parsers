#!/usr/bin/env python3
"""
test_raw_hive_scrape.py — Standalone test of the raw byte-scraping fallback
technique for extracting hostname/IP from a (possibly damaged) SYSTEM hive,
WITHOUT using regipy's structured parsing at all.

This is a diagnostic/proof-of-concept only -- run it against a real hive
(corrupt or not) to see what it actually finds, before we decide whether to
wire this into the real pipeline as a fallback.

How it works:
  1. Read the entire hive file as raw bytes (no structure parsing at all).
  2. Search for known value-NAME anchors as they appear in the hive:
       "ComputerName", "IPAddress", "DhcpIPAddress"
     These names are stored in the hive as UTF-16LE strings (registry value
     names are always UTF-16LE internally), so we search for the UTF-16LE
     encoding of each anchor string.
  3. For each hit, look at a window of bytes immediately following it and
     try to decode plausible UTF-16LE text out of that window -- this is
     where the actual VALUE (the computer name, or an IP address) usually
     sits, since value name and value data are typically stored close
     together in the same cell.
  4. Filter candidates: hostnames must look like a sane computer name
     (alnum/hyphen, reasonable length), IPs must parse as valid IPv4.

Usage:
  python3 test_raw_hive_scrape.py /path/to/SYSTEM
"""

import re
import sys
import ipaddress
from pathlib import Path

# Anchors, encoded as UTF-16LE (no BOM) -- this is how value NAMES are
# actually stored inside a registry hive's cell structure.
ANCHORS = {
    "ComputerName": "ComputerName".encode("utf-16-le"),
    "IPAddress": "IPAddress".encode("utf-16-le"),
    "DhcpIPAddress": "DhcpIPAddress".encode("utf-16-le"),
}

WINDOW_SIZE = 256  # bytes to inspect after each anchor hit

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}[A-Za-z0-9]?$")


def find_anchor_offsets(data: bytes, anchor_bytes: bytes) -> list[int]:
    offsets = []
    start = 0
    while True:
        idx = data.find(anchor_bytes, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def extract_utf16_strings(window: bytes) -> list[str]:
    """
    Pull out plausible UTF-16LE decoded substrings from a byte window.

    Registry string values are null-terminated UTF-16LE. Rather than trying
    every possible (start, length) pair -- which produces a flood of
    overlapping substrings/fragments, most of them junk -- this scans each
    even-aligned start offset and decodes the LONGEST clean run of
    printable UTF-16LE characters up to the first null terminator or first
    non-printable character, then keeps only that longest decode per start
    offset. This is much closer to "what registry value actually sat here"
    than every short substring of it.
    """
    candidates = []
    seen_spans = set()

    for start in range(0, len(window) - 4, 2):
        chars = []
        pos = start
        while pos + 2 <= len(window):
            code_unit = window[pos:pos + 2]
            try:
                ch = code_unit.decode("utf-16-le")
            except UnicodeDecodeError:
                break
            if ch == "\x00":
                break  # null terminator -- end of string
            if not (32 <= ord(ch) < 127):
                break  # non-printable -- not real string data
            chars.append(ch)
            pos += 2

        if len(chars) >= 4:  # ignore trivially short noise
            text = "".join(chars)
            span = (start, pos)
            # Skip spans fully contained within an already-captured longer span
            if not any(s <= start and pos <= e for s, e in seen_spans):
                candidates.append(text)
                seen_spans.add(span)

    # Longest-first: the most complete decode at each start point is the
    # most likely to be the real value, not a truncated fragment of it.
    candidates.sort(key=len, reverse=True)
    return candidates


def scrape_hostname(data: bytes) -> list[str]:
    found = []
    for offset in find_anchor_offsets(data, ANCHORS["ComputerName"]):
        window = data[offset + len(ANCHORS["ComputerName"]): offset + len(ANCHORS["ComputerName"]) + WINDOW_SIZE]
        for candidate in extract_utf16_strings(window):
            if candidate.upper() in ("COMPUTERNAME", "IPADDRESS", "DHCPIPADDRESS"):
                continue
            if HOSTNAME_RE.match(candidate):
                found.append(candidate)
                break  # longest clean candidate per anchor hit is enough
    return found


def scrape_ips(data: bytes) -> list[str]:
    found = []
    for anchor_name in ("IPAddress", "DhcpIPAddress"):
        for offset in find_anchor_offsets(data, ANCHORS[anchor_name]):
            window = data[offset + len(ANCHORS[anchor_name]): offset + len(ANCHORS[anchor_name]) + WINDOW_SIZE]
            for candidate in extract_utf16_strings(window):
                if candidate.upper() in ("COMPUTERNAME", "IPADDRESS", "DHCPIPADDRESS"):
                    continue
                try:
                    addr = ipaddress.ip_address(candidate)
                    if not (addr.is_loopback or addr.is_link_local) and str(addr) != "0.0.0.0":
                        found.append(str(addr))
                        break  # longest clean candidate per anchor hit is enough
                except ValueError:
                    continue
    return found


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_raw_hive_scrape.py /path/to/SYSTEM")
        sys.exit(1)

    hive_path = Path(sys.argv[1])
    if not hive_path.exists():
        print(f"File not found: {hive_path}")
        sys.exit(1)

    print(f"Reading {hive_path} ({hive_path.stat().st_size:,} bytes)...")
    data = hive_path.read_bytes()

    print("\n=== Hostname candidates (raw scrape, no structure parsing) ===")
    hostnames = scrape_hostname(data)
    if hostnames:
        from collections import Counter
        for name, count in Counter(hostnames).most_common(10):
            print(f"  {count:4d}x  {name}")
    else:
        print("  (none found)")

    print("\n=== IP candidates (raw scrape, no structure parsing) ===")
    ips = scrape_ips(data)
    if ips:
        from collections import Counter
        for ip, count in Counter(ips).most_common(20):
            print(f"  {count:4d}x  {ip}")
    else:
        print("  (none found)")

    print("\nNOTE: this is a best-effort raw scrape with no structural")
    print("validation. Cross-check these results against what you'd expect")
    print("for this machine, and against regipy's structured output if it")
    print("partially works, before trusting them.")


if __name__ == "__main__":
    main()
