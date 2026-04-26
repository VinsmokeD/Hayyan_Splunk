#!/usr/bin/env bash
# Hayyan SOC Lab — Vulnerability Scan Orchestrator
# Runs daily at 02:30 via systemd timer (hayyan-scan.timer)
# Also callable manually: sudo /opt/hayyan-scan/orchestrator.sh
#
# Flow: nuclei → trivy → normalize → push to Splunk HEC → push to MISP (CVSS≥7)
# All output logged to /opt/hayyan-scan/logs/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PIPELINE_DIR="$SCRIPT_DIR/pipeline"
SCANNERS_DIR="$SCRIPT_DIR/scanners"
RAW_DIR="$SCRIPT_DIR/raw"
HEC_ENV="$SCRIPT_DIR/config/splunk_hec.env"

SCAN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/scan-$SCAN_ID.log"

mkdir -p "$LOG_DIR" "$RAW_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Hayyan Scan Orchestrator — $SCAN_ID ==="
echo "Started: $(date)"
echo ""

# ── Sanity checks ─────────────────────────────────────────────────────────────
if [[ ! -f "$HEC_ENV" ]]; then
    echo "ERROR: $HEC_ENV not found. Copy config/splunk_hec.env.example and fill in your HEC token."
    exit 1
fi

# Load HEC credentials (chmod 600 this file)
# shellcheck source=/dev/null
source "$HEC_ENV"

if [[ -z "${SPLUNK_HEC_TOKEN:-}" ]]; then
    echo "ERROR: SPLUNK_HEC_TOKEN not set in $HEC_ENV"
    exit 1
fi

if ! command -v nuclei &>/dev/null; then
    echo "ERROR: nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

if ! command -v trivy &>/dev/null; then
    echo "ERROR: trivy not found. Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# ── Nuclei — web / network scans ──────────────────────────────────────────────
echo "--- Running Nuclei scans ---"

bash "$SCANNERS_DIR/nuclei_web.sh"   "$SCAN_ID" "$RAW_DIR" || echo "WARN: nuclei_web returned non-zero"
bash "$SCANNERS_DIR/nuclei_dc01.sh"  "$SCAN_ID" "$RAW_DIR" || echo "WARN: nuclei_dc01 returned non-zero"

echo ""

# ── Trivy — filesystem + container scans ──────────────────────────────────────
echo "--- Running Trivy scans ---"

bash "$SCANNERS_DIR/trivy_fs.sh" "$SCAN_ID" "$RAW_DIR" || echo "WARN: trivy_fs returned non-zero"

echo ""

# ── Normalize all raw JSON into unified schema ────────────────────────────────
echo "--- Normalizing results ---"

NORMALIZED="$RAW_DIR/normalized-$SCAN_ID.jsonl"

python3 "$PIPELINE_DIR/normalize.py" \
    --scan-id "$SCAN_ID" \
    --raw-dir "$RAW_DIR" \
    --output "$NORMALIZED"

FINDING_COUNT=$(wc -l < "$NORMALIZED" || echo 0)
echo "Normalized $FINDING_COUNT findings → $NORMALIZED"
echo ""

if [[ "$FINDING_COUNT" -eq 0 ]]; then
    echo "No findings to push. Done."
    echo "Finished: $(date)"
    exit 0
fi

# ── Push findings to Splunk HEC ───────────────────────────────────────────────
echo "--- Pushing to Splunk HEC ---"

python3 "$PIPELINE_DIR/push_splunk.py" \
    --normalized "$NORMALIZED" \
    --hec-url "${SPLUNK_HEC_URL:-https://192.168.56.1:8088}" \
    --hec-token "$SPLUNK_HEC_TOKEN" \
    --index "${SPLUNK_HEC_INDEX:-vuln_scans}"

echo ""

# ── Push high/critical findings to MISP ──────────────────────────────────────
echo "--- Pushing to MISP (CVSS ≥ ${MISP_MIN_CVSS:-7.0}) ---"

python3 "$PIPELINE_DIR/push_misp.py" \
    --normalized "$NORMALIZED" \
    --misp-url "${MISP_URL:-https://192.168.56.1:8443}" \
    --misp-key "${MISP_API_KEY:-}" \
    --min-cvss "${MISP_MIN_CVSS:-7.0}"

echo ""
echo "=== Scan complete: $SCAN_ID ==="
echo "Finished: $(date)"

# ── Cleanup raw files older than 7 days ───────────────────────────────────────
find "$RAW_DIR" -name "*.json" -mtime +7 -delete 2>/dev/null || true
find "$RAW_DIR" -name "*.jsonl" -mtime +7 -delete 2>/dev/null || true
find "$LOG_DIR" -name "*.log" -mtime +30 -delete 2>/dev/null || true
