#!/usr/bin/env bash
# =============================================================================
# Hayyan SOC Lab — Nuclei Web/Network Scanner Wrapper
# /opt/hayyan-scan/scanners/nuclei-web.sh
#
# Args: $1=RAW_DIR $2=SCAN_ID
# Output: $RAW_DIR/nuclei-<SCAN_ID>.json
# =============================================================================
set -euo pipefail

RAW_DIR="${1:?RAW_DIR required}"
SCAN_ID="${2:?SCAN_ID required}"
CONFIG_DIR="/opt/hayyan-scan/config"
TARGETS_FILE="$CONFIG_DIR/targets.yaml"
OUTPUT_FILE="$RAW_DIR/nuclei-${SCAN_ID}.json"
TARGET_LIST_FILE="$RAW_DIR/nuclei-targets-${SCAN_ID}.txt"

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "[Nuclei] ERROR: targets file not found at $TARGETS_FILE"
    exit 1
fi

# Extract only nuclei_targets list items, stripping inline comments safely.
awk '
    /^nuclei_targets:/ { in_targets=1; next }
    in_targets && /^[^[:space:]-]/ { in_targets=0 }
    in_targets && /^[[:space:]]*-/ {
        line=$0
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        sub(/[[:space:]]+#.*/, "", line)
        if (line != "") print line
    }
' "$TARGETS_FILE" > "$TARGET_LIST_FILE"

if [[ ! -s "$TARGET_LIST_FILE" ]]; then
    echo "[Nuclei] WARN: No nuclei_targets found in $TARGETS_FILE"
    exit 0
fi

TARGET_COUNT=$(wc -l < "$TARGET_LIST_FILE" | tr -d ' ')
echo "[Nuclei] Target file: $TARGET_LIST_FILE ($TARGET_COUNT targets)"
echo "[Nuclei] Output:  $OUTPUT_FILE"
echo "[Nuclei] Severity: medium,high,critical"

# Run Nuclei with:
#   -severity: skip info/low to reduce noise
#   -json: machine-readable output per finding
#   -stats: print progress to stderr
#   -timeout 10: per-request timeout
#   -rate-limit 50: be kind to the lab network
#   -silent: suppress banner
nuclei \
    -list "$TARGET_LIST_FILE" \
    -severity medium,high,critical \
    -json-export "$OUTPUT_FILE" \
    -stats \
    -timeout 10 \
    -rate-limit 50 \
    -silent \
    -etags "dos,fuzz" \
    2>&1 | grep -v "^\[INF\]" || true  # Suppress verbose INF lines in logs

FINDING_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
echo "[Nuclei] Wrote $FINDING_COUNT findings to $OUTPUT_FILE"
