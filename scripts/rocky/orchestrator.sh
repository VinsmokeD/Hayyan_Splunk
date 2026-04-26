#!/usr/bin/env bash
# =============================================================================
# Hayyan SOC Lab — Rocky Linux Scanner Orchestrator
# /opt/hayyan-scan/orchestrator.sh
#
# Runs Nuclei + Trivy scans, normalizes, and pushes to Splunk HEC.
# Invoked by systemd hayyan-scan.service (triggered by hayyan-scan.timer).
#
# Usage:
#   sudo /opt/hayyan-scan/orchestrator.sh            # full scan
#   sudo /opt/hayyan-scan/orchestrator.sh --nuclei   # Nuclei only
#   sudo /opt/hayyan-scan/orchestrator.sh --trivy    # Trivy only
# =============================================================================
set -euo pipefail

SCAN_HOME="/opt/hayyan-scan"
LOG_DIR="$SCAN_HOME/logs"
PIPELINE_DIR="$SCAN_HOME/pipeline"
SCANNERS_DIR="$SCAN_HOME/scanners"
CONFIG_DIR="$SCAN_HOME/config"

# Unique scan ID — used to correlate all findings from this run
SCAN_ID="run-$(date +%Y%m%d-%H%M%S)"
SCAN_LOG="$LOG_DIR/scan-${SCAN_ID}.log"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$SCAN_LOG") 2>&1

echo "================================================================"
echo " Hayyan SOC Scanner — $SCAN_ID"
echo " Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"

# ── Argument parsing ──────────────────────────────────────────────────────────
RUN_NUCLEI=true
RUN_TRIVY=true

for arg in "$@"; do
    case "$arg" in
        --nuclei) RUN_NUCLEI=true; RUN_TRIVY=false ;;
        --trivy)  RUN_NUCLEI=false; RUN_TRIVY=true ;;
    esac
done

# ── Raw output directory for this run ────────────────────────────────────────
RAW_DIR="$LOG_DIR/raw-${SCAN_ID}"
mkdir -p "$RAW_DIR"

# ── Nuclei scan ───────────────────────────────────────────────────────────────
if $RUN_NUCLEI; then
    echo ""
    echo ">>> [Nuclei] Starting web/network scan..."
    if bash "$SCANNERS_DIR/nuclei-web.sh" "$RAW_DIR" "$SCAN_ID"; then
        echo ">>> [Nuclei] Scan complete."
    else
        echo ">>> [Nuclei] WARN: scan exited non-zero (may have partial results)"
    fi
fi

# ── Trivy scan ────────────────────────────────────────────────────────────────
if $RUN_TRIVY; then
    echo ""
    echo ">>> [Trivy] Starting filesystem/container scan..."
    if bash "$SCANNERS_DIR/trivy-fs.sh" "$RAW_DIR" "$SCAN_ID"; then
        echo ">>> [Trivy] Scan complete."
    else
        echo ">>> [Trivy] WARN: scan exited non-zero (may have partial results)"
    fi
fi

# ── Normalize findings ────────────────────────────────────────────────────────
echo ""
echo ">>> [Pipeline] Normalizing findings to unified schema..."
NORMALIZED="$LOG_DIR/normalized-${SCAN_ID}.jsonl"

python3 "$PIPELINE_DIR/normalize.py" \
    --raw-dir "$RAW_DIR" \
    --output "$NORMALIZED" \
    --scan-id "$SCAN_ID"

FINDING_COUNT=$(wc -l < "$NORMALIZED" 2>/dev/null || echo 0)
echo ">>> [Pipeline] $FINDING_COUNT findings normalized."

# ── Push to Splunk ────────────────────────────────────────────────────────────
if [[ $FINDING_COUNT -gt 0 ]]; then
    echo ""
    echo ">>> [Pipeline] Pushing to Splunk HEC (index=vuln_scans)..."
    python3 "$PIPELINE_DIR/push_splunk.py" \
        --input "$NORMALIZED" \
        --scan-id "$SCAN_ID"

    # ── Mirror critical/high findings to MISP ────────────────────────────────
    echo ">>> [Pipeline] Checking for critical findings to mirror to MISP..."
    python3 "$PIPELINE_DIR/push_misp.py" \
        --input "$NORMALIZED" \
        --scan-id "$SCAN_ID" \
        --min-cvss 7.0
fi

echo ""
echo "================================================================"
echo " Scan complete: $SCAN_ID"
echo " Findings: $FINDING_COUNT"
echo " Log: $SCAN_LOG"
echo " Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
