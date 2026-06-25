#!/usr/bin/env python3
"""
diagnose_hive_encoding.py — Figure out how 'ComputerName' / 'IPAddress' are
ACTUALLY encoded in a real hive file, before writing any extraction logic
against an assumption. Searches for the anchor string in several candidate
encodings and reports which ones actually appear, with surrounding byte
context so we can see the real structure with our own eyes.

Usage:
  python3 diagnose_hive_encoding.py /path/to/SYSTEM
"""

import sys
from pathlib import Path


def hexdump_context(data: bytes, offset: int, before: int = 16, after: int = 64) -> str:
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"offset={offset} (showing {start}..{end})\n  hex:   {hex_part}\n  ascii: {ascii_part}"


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 diagnose_hive_encoding.py /path/to/SYSTEM")
        sys.exit(1)

    hive_path = Path(sys.argv[1])
    data = hive_path.read_bytes()
    print(f"Loaded {hive_path} ({len(data):,} bytes)\n")

    anchor = "ComputerName"

    encodings_to_try = {
        "UTF-16LE (no BOM)": anchor.encode("utf-16-le"),
        "Plain ASCII (1 byte/char, 'compressed' name format)": anchor.encode("ascii"),
        "UTF-16BE (no BOM)": anchor.encode("utf-16-be"),
    }

    any_found = False
    for label, needle in encodings_to_try.items():
        count = data.count(needle)
        print(f"[{label}] pattern length={len(needle)} bytes -> {count} occurrence(s)")
        if count > 0:
            any_found = True
            first_offset = data.find(needle)
            print(hexdump_context(data, first_offset))
            print()

    if not any_found:
        print("\nNo encoding of 'ComputerName' matched at all.")
        print("Possible reasons:")
        print("  - This SYSTEM hive genuinely doesn't have ComputerName written")
        print("    in a form that's a contiguous byte run (could be split across")
        print("    a cell boundary, or compressed differently than assumed).")
        print("  - Try a different, definitely-present string instead, e.g. search")
        print("    for the literal hostname you already know (e.g. IACIS-HDD-2014)")
        print("    directly, in both encodings, to at least confirm it's IN here")
        print("    somewhere and see what form it takes.")
        return

    print("=" * 70)
    print(f"Found {label} -- use this as the basis for the real extraction logic.")


if __name__ == "__main__":
    main()
