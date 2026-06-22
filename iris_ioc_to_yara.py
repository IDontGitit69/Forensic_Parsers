#!/usr/bin/env python3
"""
DFIR-IRIS IOC to YARA Rule Generator
Connects to an IRIS instance, lets you pick a case, and generates a .yar bundle.
"""

import requests
import urllib3
import socket
import struct
import re
import os
import sys

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Config ────────────────────────────────────────────────────────────────────

def get_config():
    print("=== DFIR-IRIS IOC → YARA Generator ===\n")
    while True:
        host = input("IRIS host (e.g. https://192.168.179.1:8443): ").strip().rstrip("/")
        if not host:
            print("  [!] Host cannot be empty.")
        elif not host.startswith("http://") and not host.startswith("https://"):
            print("  [!] Host must start with http:// or https://")
        else:
            break
    while True:
        api_key = input("API key: ").strip()
        if not api_key:
            print("  [!] API key cannot be empty.")
        else:
            break
    return host, api_key


# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(host, api_key, path, params=None):
    url = f"{host}{path}"
    headers = {"Authorization": f"Bearer {api_key}"}
    r = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
    r.raise_for_status()
    data = r.json()
    if data.get("status") != "success":
        raise RuntimeError(f"API error: {data.get('message', 'unknown')}")
    return data["data"]


def list_cases(host, api_key):
    data = api_get(host, api_key, "/manage/cases/list")
    return data  # list of case dicts


def list_iocs(host, api_key, case_id):
    data = api_get(host, api_key, "/case/ioc/list", params={"cid": case_id})
    return data.get("ioc", [])


# ── YARA helpers ──────────────────────────────────────────────────────────────

def sanitize_rule_name(value):
    """Turn an IOC value into a valid YARA rule name."""
    name = re.sub(r"[^a-zA-Z0-9_]", "_", value)
    name = re.sub(r"_+", "_", name).strip("_")
    return f"IOC_{name}"


def is_ipv4(value):
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        return False


def is_ipv6(value):
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def is_domain(value):
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(value))


def is_md5(value):
    return bool(re.match(r"^[a-fA-F0-9]{32}$", value))


def is_sha1(value):
    return bool(re.match(r"^[a-fA-F0-9]{40}$", value))


def is_sha256(value):
    return bool(re.match(r"^[a-fA-F0-9]{64}$", value))


def is_url(value):
    return value.startswith(("http://", "https://", "ftp://"))


def ipv4_to_hex(ip):
    packed = socket.inet_aton(ip)
    return " ".join(f"{b:02X}" for b in packed)


def ipv6_to_hex(ip):
    packed = socket.inet_pton(socket.AF_INET6, ip)
    return " ".join(f"{b:02X}" for b in packed)


def build_yara_rule(ioc_value, ioc_description, ioc_type):
    """Build a comprehensive YARA rule for a given IOC."""
    rule_name = sanitize_rule_name(ioc_value)
    desc_escaped = ioc_description.replace('"', "'")
    ioc_type_lower = (ioc_type or "").lower()

    strings_block = []
    condition_parts = []

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if is_ipv4(ioc_value) or "ip" in ioc_type_lower:
        if is_ipv4(ioc_value):
            hex_bytes = ipv4_to_hex(ioc_value)
            strings_block.append(f'        $ip_ascii   = "{ioc_value}"')
            strings_block.append(f'        $ip_wide    = "{ioc_value}" wide')
            strings_block.append(f'        $ip_bin     = {{ {hex_bytes} }}')
            condition_parts.append("any of ($ip_ascii, $ip_wide, $ip_bin)")

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    elif is_ipv6(ioc_value):
        hex_bytes = ipv6_to_hex(ioc_value)
        strings_block.append(f'        $ip6_ascii  = "{ioc_value}"')
        strings_block.append(f'        $ip6_wide   = "{ioc_value}" wide')
        strings_block.append(f'        $ip6_bin    = {{ {hex_bytes} }}')
        condition_parts.append("any of ($ip6_ascii, $ip6_wide, $ip6_bin)")

    # ── Domain ────────────────────────────────────────────────────────────────
    elif is_domain(ioc_value) or "domain" in ioc_type_lower or "hostname" in ioc_type_lower:
        strings_block.append(f'        $domain_ascii = "{ioc_value}" nocase')
        strings_block.append(f'        $domain_wide  = "{ioc_value}" wide nocase')
        condition_parts.append("any of ($domain_ascii, $domain_wide)")

    # ── URL ───────────────────────────────────────────────────────────────────
    elif is_url(ioc_value) or "url" in ioc_type_lower:
        safe_val = ioc_value.replace("\\", "\\\\").replace('"', '\\"')
        strings_block.append(f'        $url_ascii  = "{safe_val}" nocase')
        strings_block.append(f'        $url_wide   = "{safe_val}" wide nocase')
        condition_parts.append("any of ($url_ascii, $url_wide)")

    # ── MD5 ───────────────────────────────────────────────────────────────────
    elif is_md5(ioc_value) or "md5" in ioc_type_lower:
        strings_block.append(f'        $md5_ascii  = "{ioc_value}" nocase')
        strings_block.append(f'        $md5_wide   = "{ioc_value}" wide nocase')
        condition_parts.append("any of ($md5_ascii, $md5_wide)")

    # ── SHA1 ──────────────────────────────────────────────────────────────────
    elif is_sha1(ioc_value) or "sha1" in ioc_type_lower:
        strings_block.append(f'        $sha1_ascii = "{ioc_value}" nocase')
        strings_block.append(f'        $sha1_wide  = "{ioc_value}" wide nocase')
        condition_parts.append("any of ($sha1_ascii, $sha1_wide)")

    # ── SHA256 ────────────────────────────────────────────────────────────────
    elif is_sha256(ioc_value) or "sha256" in ioc_type_lower:
        strings_block.append(f'        $sha256_ascii = "{ioc_value}" nocase')
        strings_block.append(f'        $sha256_wide  = "{ioc_value}" wide nocase')
        condition_parts.append("any of ($sha256_ascii, $sha256_wide)")

    # ── Generic / email / filename / other ────────────────────────────────────
    else:
        safe_val = ioc_value.replace("\\", "\\\\").replace('"', '\\"')
        strings_block.append(f'        $str_ascii  = "{safe_val}" nocase')
        strings_block.append(f'        $str_wide   = "{safe_val}" wide nocase')
        condition_parts.append("any of ($str_ascii, $str_wide)")

    strings_section = "\n".join(strings_block)
    condition_section = " or\n        ".join(condition_parts)

    rule = f"""rule {rule_name}
{{
    meta:
        description = "{desc_escaped}"
        ioc_type    = "{ioc_type}"
        ioc_value   = "{ioc_value}"

    strings:
{strings_section}

    condition:
        {condition_section}
}}
"""
    return rule


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    host, api_key = get_config()

    # List cases
    print("\nFetching cases...\n")
    try:
        cases = list_cases(host, api_key)
    except Exception as e:
        print(f"[ERROR] Could not fetch cases: {e}")
        sys.exit(1)

    if not cases:
        print("No cases found.")
        sys.exit(0)

    print(f"{'#':<5} {'Case ID':<10} {'Name':<40} {'Status'}")
    print("-" * 75)
    for i, c in enumerate(cases, 1):
        print(f"{i:<5} {c['case_id']:<10} {c['case_name']:<40} {c.get('state_name') or 'Unknown'}")

    print()
    while True:
        try:
            choice = int(input("Select a case by # : "))
            if 1 <= choice <= len(cases):
                break
            print(f"Please enter a number between 1 and {len(cases)}")
        except ValueError:
            print("Invalid input.")

    selected = cases[choice - 1]
    case_id = selected["case_id"]
    case_name = selected["case_name"]

    print(f"\nFetching IOCs for: {case_name}...\n")
    try:
        iocs = list_iocs(host, api_key, case_id)
    except Exception as e:
        print(f"[ERROR] Could not fetch IOCs: {e}")
        sys.exit(1)

    if not iocs:
        print("No IOCs found in this case.")
        sys.exit(0)

    print(f"Found {len(iocs)} IOC(s):\n")
    for ioc in iocs:
        print(f"  [{ioc['ioc_type']}] {ioc['ioc_value']}")
        print(f"    {ioc.get('ioc_description', '(no description)')}\n")

    # Build YARA bundle
    safe_case_name = re.sub(r"[^a-zA-Z0-9_]", "_", case_name)
    safe_case_name = re.sub(r"_+", "_", safe_case_name).strip("_")
    output_file = f"{safe_case_name}.yar"

    rules = []
    for ioc in iocs:
        rule = build_yara_rule(
            ioc_value=ioc.get("ioc_value", ""),
            ioc_description=ioc.get("ioc_description", "No description provided."),
            ioc_type=ioc.get("ioc_type", "unknown"),
        )
        rules.append(rule)

    bundle = f"// YARA Rule Bundle\n// Case: {case_name}\n// Generated by iris_ioc_to_yara.py\n\n"
    bundle += "\n".join(rules)

    with open(output_file, "w") as f:
        f.write(bundle)

    print(f"\n[✓] YARA bundle written to: {output_file}")
    print(f"    {len(rules)} rule(s) generated.")


if __name__ == "__main__":
    main()
