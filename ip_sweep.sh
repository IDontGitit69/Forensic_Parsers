#!/bin/bash
# ip_sweep.sh — sweep extracted ESXi files for IPv4 addresses
# Usage: ./ip_sweep.sh /path/to/extracted/files

TARGET_DIR="${1:-.}"
OUT_RAW="ip_sweep_raw.txt"
OUT_SUMMARY="ip_sweep_summary.txt"

# Regex for IPv4 (basic — allows 0-999 per octet, filtered properly below)
IP_REGEX='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

echo "Scanning $TARGET_DIR for IPv4-shaped strings..."
echo "" > "$OUT_RAW"

# Recursively grep all files (binary-safe with -a), show filename + line
grep -rEao "$IP_REGEX" --binary-files=text -H "$TARGET_DIR" > "$OUT_RAW" 2>/dev/null

# Validate octets are 0-255 and filter obvious junk (version strings, broadcast, localhost, etc.)
echo "Filtering and ranking results..."

awk -F: '{print $1, $2}' "$OUT_RAW" | while read -r file ip; do
    valid=true
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        if [ "$o" -gt 255 ] 2>/dev/null; then valid=false; fi
    done
    # skip common noise
    case "$ip" in
        0.0.0.0|255.255.255.255|127.*|1.2.3.4) valid=false ;;
    esac
    if $valid; then
        echo "$ip|$file"
    fi
done > ip_sweep_filtered.txt

echo ""
echo "=== Top IPs by frequency (likely candidates first) ==="
cut -d'|' -f1 ip_sweep_filtered.txt | sort | uniq -c | sort -rn | head -30 | tee "$OUT_SUMMARY"

echo ""
echo "=== Which files each top IP appears in ==="
top_ips=$(cut -d'|' -f1 ip_sweep_filtered.txt | sort | uniq -c | sort -rn | head -10 | awk '{print $2}')
for ip in $top_ips; do
    echo "--- $ip ---"
    grep "^$ip|" ip_sweep_filtered.txt | cut -d'|' -f2 | sort -u
    echo ""
done >> "$OUT_SUMMARY"

echo ""
echo "Done. Full summary saved to $OUT_SUMMARY"
echo "Raw matches saved to $OUT_RAW"
