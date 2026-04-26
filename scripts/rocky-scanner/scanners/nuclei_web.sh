#!/usr/bin/env bash
# Nuclei — web application + nginx scan
# Targets: Rocky Linux nginx (192.168.56.20) and Splunk web UI (192.168.56.1:8089)
# Called by orchestrator.sh with: SCAN_ID RAW_DIR

set -euo pipefail

SCAN_ID="${1:?SCAN_ID required}"
RAW_DIR="${2:?RAW_DIR required}"

OUTPUT="$RAW_DIR/nuclei_web-$SCAN_ID.json"

# Update templates silently on first run of the day
nuclei -update-templates -silent 2>/dev/null || true

echo "[nuclei_web] Scanning web targets (Rocky + Splunk UI)..."

nuclei \
    -targets "http://192.168.56.20,https://192.168.56.20,https://192.168.56.1:8089" \
    -severity medium,high,critical \
    -exclude-tags dos,fuzz,helpers,auth-bypass \
    -rate-limit 25 \
    -timeout 5 \
    -retries 1 \
    -json \
    -output "$OUTPUT" \
    -silent \
    -no-color \
    2>&1 | grep -v "^\[" || true   # suppress template loading noise

COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
echo "[nuclei_web] Done — $COUNT findings → $OUTPUT"
