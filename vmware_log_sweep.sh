#!/bin/bash
# vmware_log_sweep.sh — extract Hostname and IP+interface values from all vmware.log files
# Usage: ./vmware_log_sweep.sh /path/to/datastore/partition

TARGET_DIR="${1:-.}"

echo "Searching for vmware.log files under $TARGET_DIR ..."
LOG_FILES=$(find "$TARGET_DIR" -iname "vmware*.log" 2>/dev/null)

if [ -z "$LOG_FILES" ]; then
    echo "No vmware*.log files found under $TARGET_DIR"
    exit 1
fi

echo "Found $(echo "$LOG_FILES" | wc -l) files."
echo ""

# --- Hostnames ---
echo "=== Unique Hostname values (with counts) ==="
grep -hoE 'Hostname=[^[:space:]]+' $LOG_FILES \
    | sort | uniq -c | sort -rn

echo ""

# --- IP + interface pairs ---
echo "=== Unique IP=<ip> (<interface>) values (with counts) ==="
grep -hoE 'IP=[0-9.]+ \([^)]+\)' $LOG_FILES \
    | sort | uniq -c | sort -rn

echo ""

# --- Optional: also show which files each top hostname/IP came from ---
echo "=== File breakdown (which logs contain which Hostname) ==="
grep -loE 'Hostname=[^[:space:]]+' $LOG_FILES | while read -r f; do
    hn=$(grep -oE 'Hostname=[^[:space:]]+' "$f" | sort -u)
    echo "$f -> $hn"
done

echo ""
echo "=== File breakdown (which logs contain which IP/interface) ==="
grep -loE 'IP=[0-9.]+ \([^)]+\)' $LOG_FILES | while read -r f; do
    ipv=$(grep -oE 'IP=[0-9.]+ \([^)]+\)' "$f" | sort -u | tr '\n' ';')
    echo "$f -> $ipv"
done
