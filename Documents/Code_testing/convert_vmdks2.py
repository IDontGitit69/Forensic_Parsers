#!/bin/bash
# ============================================================
# VMDK Sesparse Merger
#
# Scans a directory for VMDK descriptor files and intelligently
# pairs snapshot descriptors (file1) with their base descriptors
# (file2) by parsing the descriptor contents directly.
#
# For each pair:
#   1. Runs: qemu-img convert -f vmdk -O vmdk <file1> <output>
#      Output is named after file2 and placed in OUTPUT_DIR
#   2. Moves the flat extent (parsed from file2) into OUTPUT_DIR
#
# Usage:
#   ./merge_sesparse.sh [source_directory]
#   Defaults to current directory if no argument given.
# ============================================================

SOURCE_DIR="${1:-.}"
OUTPUT_DIR="${SOURCE_DIR}/merged"
MAX_PARALLEL=4
LOG_FILE="${OUTPUT_DIR}/merge.log"

# --- Helpers ---
log() {
    echo "$1" | tee -a "$LOG_FILE"
}

log_tag() {
    local TAG="$1"
    local MSG="$2"
    printf "[%-5s] %s | %s\n" "$TAG" "$(date '+%H:%M:%S')" "$MSG" | tee -a "$LOG_FILE"
}

is_descriptor() {
    # Returns 0 (true) if the first line of the file is "# Disk DescriptorFile"
    local FILE="$1"
    head -n 1 "$FILE" 2>/dev/null | grep -q "# Disk DescriptorFile"
}

get_parent_hint() {
    # Extracts the value of parentFileNameHint from a descriptor
    # e.g. parentFileNameHint="image1.vmdk" -> image1.vmdk
    local FILE="$1"
    grep -m1 'parentFileNameHint' "$FILE" \
        | sed 's/.*parentFileNameHint="\([^"]*\)".*/\1/'
}

get_extent_file() {
    # Parses the extent description line and extracts the filename
    # Line format: RW <sectors> <type> "filename"
    local FILE="$1"
    grep -A5 '# Extent description' "$FILE" \
        | grep -m1 '^RW' \
        | sed 's/.*"\([^"]*\)".*/\1/'
}

# --- Setup ---
mkdir -p "$OUTPUT_DIR"
echo "============================================" | tee "$LOG_FILE"
echo " VMDK Sesparse Merger - $(date)"             | tee -a "$LOG_FILE"
echo " Source:  $SOURCE_DIR"                       | tee -a "$LOG_FILE"
echo " Output:  $OUTPUT_DIR"                       | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# --- Phase 1: Find and classify all descriptor files ---
log "[INFO] Scanning for VMDK descriptor files in: $SOURCE_DIR"
echo "" | tee -a "$LOG_FILE"

declare -a SNAPSHOT_DESCS   # file1: snapshot descriptors (extent = sesparse)
declare -a BASE_DESCS       # file2: base descriptors     (extent = flat)

while IFS= read -r -d '' VMDK; do
    if ! is_descriptor "$VMDK"; then
        continue
    fi

    EXTENT=$(get_extent_file "$VMDK")

    if [[ "$EXTENT" == *"-sesparse.vmdk" ]]; then
        SNAPSHOT_DESCS+=("$VMDK")
        log_tag "DESC" "Snapshot descriptor: $VMDK  (extent: $EXTENT)"
    elif [[ "$EXTENT" == *"-flat.vmdk" ]]; then
        BASE_DESCS+=("$VMDK")
        log_tag "DESC" "Base descriptor:     $VMDK  (extent: $EXTENT)"
    else
        log_tag "SKIP" "Unrecognised extent type, skipping: $VMDK (extent: $EXTENT)"
    fi
done < <(find "$SOURCE_DIR" -maxdepth 1 -name "*.vmdk" ! -name "*-flat.vmdk" ! -name "*-sesparse.vmdk" -print0 | sort -z)

echo "" | tee -a "$LOG_FILE"

if [ ${#SNAPSHOT_DESCS[@]} -eq 0 ]; then
    log "[ERROR] No snapshot descriptor files found. Nothing to do."
    exit 1
fi

# --- Phase 2: Pair each snapshot descriptor with its base descriptor ---
log "[INFO] Pairing snapshot descriptors with base descriptors..."
echo "" | tee -a "$LOG_FILE"

declare -a PAIRS_FILE1   # snapshot descriptor paths
declare -a PAIRS_FILE2   # matched base descriptor paths

for FILE1 in "${SNAPSHOT_DESCS[@]}"; do
    PARENT_HINT=$(get_parent_hint "$FILE1")

    if [ -z "$PARENT_HINT" ]; then
        log_tag "WARN" "No parentFileNameHint found in $FILE1 — skipping"
        continue
    fi

    # Find the base descriptor whose filename matches the parent hint
    MATCHED=""
    for FILE2 in "${BASE_DESCS[@]}"; do
        if [ "$(basename "$FILE2")" = "$PARENT_HINT" ]; then
            MATCHED="$FILE2"
            break
        fi
    done

    if [ -z "$MATCHED" ]; then
        log_tag "WARN" "No base descriptor found matching '$PARENT_HINT' for $FILE1 — skipping"
        continue
    fi

    PAIRS_FILE1+=("$FILE1")
    PAIRS_FILE2+=("$MATCHED")
    log_tag "PAIR" "$(basename "$FILE1")  ->  $(basename "$MATCHED")"
done

echo "" | tee -a "$LOG_FILE"

if [ ${#PAIRS_FILE1[@]} -eq 0 ]; then
    log "[ERROR] No valid pairs found. Check descriptor contents."
    exit 1
fi

log "[INFO] Found ${#PAIRS_FILE1[@]} pair(s) to process."
echo "" | tee -a "$LOG_FILE"

# --- Phase 3: Merge function ---
merge_pair() {
    local FILE1="$1"
    local FILE2="$2"

    local OUTPUT_NAME
    OUTPUT_NAME=$(basename "$FILE2")                          # e.g. image1.vmdk
    local OUTPUT_VMDK="${OUTPUT_DIR}/${OUTPUT_NAME}"

    # Parse the flat extent filename from file2
    local FLAT_NAME
    FLAT_NAME=$(get_extent_file "$FILE2")                     # e.g. image1-flat.vmdk
    local FLAT_SRC="${SOURCE_DIR}/${FLAT_NAME}"
    local FLAT_DST="${OUTPUT_DIR}/${FLAT_NAME}"

    local START_TIME
    START_TIME=$(date +%s)

    log_tag "START" "$(basename "$FILE1")  ->  $OUTPUT_VMDK"

    # Run the merge
    qemu-img convert \
        -f vmdk \
        -O vmdk \
        -p \
        "$FILE1" "$OUTPUT_VMDK" 2>&1 | while IFS= read -r line; do
            echo "        [$(basename "$FILE1" .vmdk)] $line"
        done

    local EXIT_CODE=${PIPESTATUS[0]}
    local ELAPSED=$(( $(date +%s) - START_TIME ))

    if [ $EXIT_CODE -eq 0 ]; then
        local SIZE
        SIZE=$(du -h "$OUTPUT_VMDK" 2>/dev/null | cut -f1)
        log_tag "DONE" "$(basename "$FILE1") -> $OUTPUT_VMDK | Size: $SIZE | Elapsed: ${ELAPSED}s"

        # Move the flat extent into the output directory
        if [ -f "$FLAT_SRC" ]; then
            log_tag "MOVE" "$FLAT_SRC  ->  $FLAT_DST"
            mv "$FLAT_SRC" "$FLAT_DST"
            if [ $? -eq 0 ]; then
                local FLAT_SIZE
                FLAT_SIZE=$(du -h "$FLAT_DST" 2>/dev/null | cut -f1)
                log_tag "MOVE" "Done | $FLAT_NAME | Size: $FLAT_SIZE"
            else
                log_tag "FAIL" "Could not move flat file: $FLAT_SRC"
            fi
        else
            log_tag "WARN" "Flat file not found, skipping move: $FLAT_SRC"
        fi
    else
        log_tag "FAIL" "$(basename "$FILE1") | qemu-img exit code: $EXIT_CODE | Elapsed: ${ELAPSED}s"
    fi
}

export -f merge_pair get_extent_file get_parent_hint log log_tag
export OUTPUT_DIR SOURCE_DIR LOG_FILE

# --- Phase 4: Parallel execution ---
log "[INFO] Starting merge (max $MAX_PARALLEL parallel jobs)..."
echo "" | tee -a "$LOG_FILE"

if command -v parallel &>/dev/null; then
    # Build a tab-separated list of pairs for GNU parallel
    PAIR_LIST=""
    for i in "${!PAIRS_FILE1[@]}"; do
        PAIR_LIST+="${PAIRS_FILE1[$i]}"$'\t'"${PAIRS_FILE2[$i]}"$'\n'
    done
    printf '%s' "$PAIR_LIST" | parallel -j "$MAX_PARALLEL" --colsep $'\t' merge_pair {1} {2}
else
    RUNNING=0
    PIDS=()
    for i in "${!PAIRS_FILE1[@]}"; do
        merge_pair "${PAIRS_FILE1[$i]}" "${PAIRS_FILE2[$i]}" &
        PIDS+=($!)
        RUNNING=$((RUNNING + 1))
        if [ "$RUNNING" -ge "$MAX_PARALLEL" ]; then
            wait "${PIDS[0]}"
            PIDS=("${PIDS[@]:1}")
            RUNNING=$((RUNNING - 1))
        fi
    done
    for PID in "${PIDS[@]}"; do
        wait "$PID"
    done
fi

# --- Summary ---
echo "" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo " Complete - $(date)"                         | tee -a "$LOG_FILE"
SUCCEEDED=$(grep -c "^\[DONE " "$LOG_FILE" || true)
FAILED=$(grep -c "^\[FAIL " "$LOG_FILE" || true)
echo " Pairs processed: ${#PAIRS_FILE1[@]}"        | tee -a "$LOG_FILE"
echo " Succeeded:       $SUCCEEDED"                | tee -a "$LOG_FILE"
echo " Failed:          $FAILED"                   | tee -a "$LOG_FILE"
echo " Output dir:      $OUTPUT_DIR/"              | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "[WARN] Some merges failed. Check $LOG_FILE for details."
    exit 1
fi

exit 0
