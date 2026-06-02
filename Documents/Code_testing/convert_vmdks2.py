#!/bin/bash
# ============================================================
# VMDK Snapshot Merger
# Finds snapshot descriptor VMDKs (*-00000*.vmdk), merges the
# full snapshot chain into a single output VMDK using qemu-img,
# and copies the associated -flat.vmdk alongside it.
#
# Output per disk:
#   ./merged/disk1.vmdk        <- merged snapshot chain
#   ./merged/disk1-flat.vmdk   <- copy of the original flat extent
#
# Usage: Run from the directory containing your VMDK files.
# ============================================================

OUTPUT_DIR="./merged"
MAX_PARALLEL=4          # Adjust based on your CPU/IO capacity
LOG_FILE="${OUTPUT_DIR}/conversion.log"

# --- Setup ---
mkdir -p "$OUTPUT_DIR"
echo "============================================" | tee "$LOG_FILE"
echo " VMDK Merger - $(date)"                      | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

# Find all snapshot descriptor VMDKs (excludes -flat.vmdk extents)
# Matches patterns like: disk-000001.vmdk, vm-000002.vmdk, etc.
VMDKS=($(find . -maxdepth 1 -name "*-00000*.vmdk" ! -name "*-flat.vmdk" | sort))

if [ ${#VMDKS[@]} -eq 0 ]; then
    echo "[ERROR] No snapshot VMDK descriptor files found in current directory." | tee -a "$LOG_FILE"
    echo "        Make sure you run this script from the folder containing your VMDKs." | tee -a "$LOG_FILE"
    exit 1
fi

echo "[INFO] Found ${#VMDKS[@]} snapshot VMDK(s) to merge:" | tee -a "$LOG_FILE"
for v in "${VMDKS[@]}"; do
    echo "       - $v" | tee -a "$LOG_FILE"
done
echo "" | tee -a "$LOG_FILE"

# --- Merge Function ---
merge_vmdk() {
    local INPUT="$1"
    local FILENAME="${INPUT##*/}"                        # strip leading ./
    local BASENAME="${FILENAME%.vmdk}"                   # e.g. disk1-000001

    # Strip the -00000X snapshot suffix to get the base disk name
    # e.g. disk1-000001 -> disk1
    local DISKNAME
    DISKNAME=$(echo "$BASENAME" | sed 's/-[0-9]\{6\}$//')

    local OUTPUT_VMDK="${OUTPUT_DIR}/${DISKNAME}.vmdk"
    local FLAT_SRC="./${DISKNAME}-flat.vmdk"
    local FLAT_DST="${OUTPUT_DIR}/${DISKNAME}-flat.vmdk"
    local START_TIME
    START_TIME=$(date +%s)

    echo "[START] $(date '+%H:%M:%S') | $INPUT -> $OUTPUT_VMDK" | tee -a "$LOG_FILE"

    # --- Sanity check: does the flat file exist? ---
    if [ ! -f "$FLAT_SRC" ]; then
        echo "[WARN]  $(date '+%H:%M:%S') | Flat file not found: $FLAT_SRC — skipping copy." | tee -a "$LOG_FILE"
    fi

    # --- Merge the full snapshot chain into a single VMDK ---
    qemu-img convert \
        -f vmdk \
        -O vmdk \
        -p \
        "$INPUT" "$OUTPUT_VMDK" 2>&1 | while IFS= read -r line; do
            echo "        [$DISKNAME] $line"
        done

    local EXIT_CODE=${PIPESTATUS[0]}
    local END_TIME
    END_TIME=$(date +%s)
    local ELAPSED=$((END_TIME - START_TIME))

    if [ $EXIT_CODE -eq 0 ]; then
        local SIZE
        SIZE=$(du -h "$OUTPUT_VMDK" 2>/dev/null | cut -f1)
        echo "[DONE]  $(date '+%H:%M:%S') | $INPUT -> $OUTPUT_VMDK | Size: $SIZE | Elapsed: ${ELAPSED}s" | tee -a "$LOG_FILE"

        # --- Copy the associated flat extent file ---
        if [ -f "$FLAT_SRC" ]; then
            echo "[MOVE]  $(date '+%H:%M:%S') | $FLAT_SRC -> $FLAT_DST" | tee -a "$LOG_FILE"
            mv "$FLAT_SRC" "$FLAT_DST"
            if [ $? -eq 0 ]; then
                local FLAT_SIZE
                FLAT_SIZE=$(du -h "$FLAT_DST" 2>/dev/null | cut -f1)
                echo "[MOVE]  $(date '+%H:%M:%S') | Done | Size: $FLAT_SIZE" | tee -a "$LOG_FILE"
            else
                echo "[FAIL]  $(date '+%H:%M:%S') | Failed to move flat file: $FLAT_SRC" | tee -a "$LOG_FILE"
            fi
        fi
    else
        echo "[FAIL]  $(date '+%H:%M:%S') | $INPUT | Exit code: $EXIT_CODE | Elapsed: ${ELAPSED}s" | tee -a "$LOG_FILE"
    fi
}

export -f merge_vmdk
export OUTPUT_DIR LOG_FILE

# --- Parallel Execution ---
echo "[INFO] Starting parallel merge (max $MAX_PARALLEL jobs at once)..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Use GNU parallel if available, otherwise fall back to manual background jobs
if command -v parallel &>/dev/null; then
    printf '%s\n' "${VMDKS[@]}" | parallel -j "$MAX_PARALLEL" merge_vmdk {}
else
    RUNNING=0
    PIDS=()
    for VMDK in "${VMDKS[@]}"; do
        merge_vmdk "$VMDK" &
        PIDS+=($!)
        RUNNING=$((RUNNING + 1))

        # Wait for a slot to free up if we've hit the parallel limit
        if [ "$RUNNING" -ge "$MAX_PARALLEL" ]; then
            wait "${PIDS[0]}"
            PIDS=("${PIDS[@]:1}")
            RUNNING=$((RUNNING - 1))
        fi
    done

    # Wait for all remaining background jobs
    for PID in "${PIDS[@]}"; do
        wait "$PID"
    done
fi

# --- Summary ---
echo "" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo " Merge complete - $(date)"                   | tee -a "$LOG_FILE"
SUCCEEDED=$(grep -c "^\[DONE\]" "$LOG_FILE")
FAILED=$(grep -c "^\[FAIL\]" "$LOG_FILE")
echo " Succeeded: $SUCCEEDED"                      | tee -a "$LOG_FILE"
echo " Failed:    $FAILED"                         | tee -a "$LOG_FILE"
echo " Output:    $OUTPUT_DIR/"                    | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "[WARN] Some merges failed. Check $LOG_FILE for details."
    exit 1
fi

exit 0
