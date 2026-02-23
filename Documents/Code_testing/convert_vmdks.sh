#!/bin/bash

# ============================================================
# VMDK Snapshot Flattener
# Converts all *-00000*.vmdk descriptor files to raw images
# using qemu-img, running all jobs in parallel.
# ============================================================

OUTPUT_DIR="./flattened"
MAX_PARALLEL=4          # Adjust based on your CPU/IO capacity
LOG_FILE="./flattened/conversion.log"

# --- Setup ---
mkdir -p "$OUTPUT_DIR"
echo "============================================" | tee "$LOG_FILE"
echo " VMDK Flattener - $(date)" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

# Find all snapshot descriptor VMDKs (excludes -flat.vmdk extents)
# Matches patterns like: disk-000001.vmdk, vm-000002.vmdk, etc.
VMDKS=($(find . -maxdepth 1 -name "*00000*.vmdk" ! -name "*-flat.vmdk" | sort))

if [ ${#VMDKS[@]} -eq 0 ]; then
    echo "[ERROR] No snapshot VMDK descriptor files found in current directory." | tee -a "$LOG_FILE"
    echo "        Make sure you run this script from the folder containing your VMDKs." | tee -a "$LOG_FILE"
    exit 1
fi

echo "[INFO] Found ${#VMDKS[@]} VMDK(s) to convert:" | tee -a "$LOG_FILE"
for v in "${VMDKS[@]}"; do
    echo "       - $v" | tee -a "$LOG_FILE"
done
echo "" | tee -a "$LOG_FILE"

# --- Conversion Function ---
convert_vmdk() {
    local INPUT="$1"
    local BASENAME="${INPUT%.vmdk}"
    local BASENAME="${BASENAME##*/}"          # strip path
    local OUTPUT="${OUTPUT_DIR}/${BASENAME}.img"
    local START_TIME=$(date +%s)

    echo "[START] $(date '+%H:%M:%S') | $INPUT" | tee -a "$LOG_FILE"

    qemu-img convert \
        -f vmdk \
        -O raw \
        -p \
        "$INPUT" "$OUTPUT" 2>&1 | while IFS= read -r line; do
            echo "        [$BASENAME] $line"
        done

    local EXIT_CODE=${PIPESTATUS[0]}
    local END_TIME=$(date +%s)
    local ELAPSED=$((END_TIME - START_TIME))

    if [ $EXIT_CODE -eq 0 ]; then
        local SIZE=$(du -h "$OUTPUT" 2>/dev/null | cut -f1)
        echo "[DONE]  $(date '+%H:%M:%S') | $INPUT -> $OUTPUT | Size: $SIZE | Elapsed: ${ELAPSED}s" | tee -a "$LOG_FILE"
    else
        echo "[FAIL]  $(date '+%H:%M:%S') | $INPUT | Exit code: $EXIT_CODE | Elapsed: ${ELAPSED}s" | tee -a "$LOG_FILE"
    fi
}

export -f convert_vmdk
export OUTPUT_DIR LOG_FILE

# --- Parallel Execution ---
echo "[INFO] Starting parallel conversion (max $MAX_PARALLEL jobs at once)..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Use GNU parallel if available, otherwise fall back to background jobs
if command -v parallel &>/dev/null; then
    printf '%s\n' "${VMDKS[@]}" | parallel -j "$MAX_PARALLEL" convert_vmdk {}
else
    # Manual parallel with job slot limiting
    RUNNING=0
    PIDS=()

    for VMDK in "${VMDKS[@]}"; do
        convert_vmdk "$VMDK" &
        PIDS+=($!)
        RUNNING=$((RUNNING + 1))

        # Wait for a slot to free up if we've hit the limit
        if [ "$RUNNING" -ge "$MAX_PARALLEL" ]; then
            wait "${PIDS[0]}"
            PIDS=("${PIDS[@]:1}")
            RUNNING=$((RUNNING - 1))
        fi
    done

    # Wait for all remaining jobs
    for PID in "${PIDS[@]}"; do
        wait "$PID"
    done
fi

# --- Summary ---
echo "" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo " Conversion complete - $(date)" | tee -a "$LOG_FILE"

SUCCEEDED=$(grep -c "^\[DONE\]" "$LOG_FILE")
FAILED=$(grep -c "^\[FAIL\]" "$LOG_FILE")

echo " Succeeded: $SUCCEEDED" | tee -a "$LOG_FILE"
echo " Failed:    $FAILED" | tee -a "$LOG_FILE"
echo " Output:    $OUTPUT_DIR/" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "[WARN] Some conversions failed. Check $LOG_FILE for details."
    exit 1
fi

exit 0
