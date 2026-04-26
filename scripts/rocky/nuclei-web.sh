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

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "[Nuclei] ERROR: targets file not found at $TARGETS_FILE"
    exit 1
fi

# Read web targets from YAML (simple grep for nuclei_targets list items)
TARGETS=$(grep -A 100 '^nuclei_targets:' "$TARGETS_FILE" | grep '^\s*-' | sed 's/.*- //' | tr '\n' ',')
TARGETS="${TARGETS%,}"  # Remove trailing comma

if [[ -z "$TARGETS" ]]; then
    echo "[Nuclei] WARN: No nuclei_targets found in $TARGETS_FILE"
    exit 0
fi

echo "[Nuclei] Targets: $TARGETS"
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
    -target "$TARGETS" \
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
