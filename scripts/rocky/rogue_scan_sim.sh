#!/usr/bin/env bash
# =============================================================================
# Hayyan SOC Lab — Rogue Scan Simulator
# /opt/hayyan-scan/rogue_scan_sim.sh
#
# Simulates unauthorized scanning activity to test SOC detection quality.
# "Rogue" = scanning originating from outside the authorized scanner node.
#
# Usage (from a different host or with a spoofed user-agent):
#   bash scripts/rocky/rogue_scan_sim.sh --target 192.168.56.20
#   bash scripts/rocky/rogue_scan_sim.sh --target 192.168.56.20 --intensity high
#
# Detection expectations:
#   - Nginx 404 spike → "Web Scanner Detected" alert fires
#   - Source IP ≠ 192.168.56.20 → contextual alert: source is NOT authorized scanner
#   - AI agent should note source is NOT 192.168.56.20 during triage
#
# WARNING: Only run against lab targets you control. This script is intentionally
# noisy to trigger detection. Never run against production systems.
# =============================================================================
set -euo pipefail

TARGET="192.168.56.20"
INTENSITY="medium"  # low | medium | high
ROGUE_IP="192.168.56.99"  # Simulated rogue host (documentation only)

for arg in "$@"; do
    case "$arg" in
        --target=*) TARGET="${arg#--target=}" ;;
        --target) shift; TARGET="$1" ;;
        --intensity=*) INTENSITY="${arg#--intensity=}" ;;
        --intensity) shift; INTENSITY="$1" ;;
    esac
done

echo "================================================================"
echo " [SIMULATION] Rogue Scan Simulation"
echo " Target: $TARGET"
echo " Intensity: $INTENSITY"
echo " Authorized scanner IP: 192.168.56.20 (Rocky Linux)"
echo " This simulation runs from: $(hostname -I | awk '{print $1}')"
echo " Expected: SOC should detect scan + flag source is NOT authorized"
echo "================================================================"
echo ""

# ── Intensity settings ────────────────────────────────────────────────────────
case $INTENSITY in
    low)    REQUESTS=20; DELAY=1.0 ;;
    medium) REQUESTS=60; DELAY=0.3 ;;
    high)   REQUESTS=150; DELAY=0.05 ;;
    *)      REQUESTS=60; DELAY=0.3 ;;
esac

# Paths that trigger 404s — simulating a web scanner probing for vulnerabilities
SCAN_PATHS=(
    "/admin" "/.env" "/phpinfo.php" "/wp-login.php"
    "/config.php" "/.git/config" "/backup.zip"
    "/api/v1/users" "/../../../etc/passwd"
    "/login.php" "/wp-admin/admin-ajax.php"
    "/manager/html" "/actuator/health"
    "/console" "/jmx-console" "/phpmyadmin"
    "/.DS_Store" "/robots.txt" "/sitemap.xml"
    "/api/swagger.json" "/openapi.json"
)

echo "[*] Sending $REQUESTS scanning requests to http://$TARGET ..."
echo "[*] This will trigger the 'Web Scanner Detected' alert in Splunk (~30-60s lag)"
echo ""

SENT=0
for i in $(seq 1 $REQUESTS); do
    # Cycle through scan paths
    PATH_IDX=$(( (i - 1) % ${#SCAN_PATHS[@]} ))
    SCAN_PATH="${SCAN_PATHS[$PATH_IDX]}"

    # Varying user agents (scanner fingerprints)
    USER_AGENTS=(
        "Mozilla/5.0 zgrab/0.x"
        "python-requests/2.31.0"
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
        "masscan/1.0"
        "sqlmap/1.7.2"
        "Nikto/2.1.6"
    )
    UA_IDX=$(( i % ${#USER_AGENTS[@]} ))
    UA="${USER_AGENTS[$UA_IDX]}"

    curl -sk \
        --max-time 3 \
        --user-agent "$UA" \
        "http://$TARGET$SCAN_PATH" \
        -o /dev/null \
        -w "" 2>/dev/null || true

    SENT=$((SENT + 1))
    sleep "$DELAY"

    if (( SENT % 20 == 0 )); then
        echo "[*] Sent $SENT/$REQUESTS requests..."
    fi
done

echo ""
echo "================================================================"
echo " [SIMULATION] Rogue scan complete."
echo " Sent $SENT HTTP requests to $TARGET"
echo ""
echo " Next steps for SOC analysts:"
echo "   1. Wait 30-60 seconds for Splunk alert to fire"
echo "   2. Check: index=linux_web | stats count by clientip | sort -count"
echo "   3. Note: source IP is $(hostname -I | awk '{print $1}') (NOT 192.168.56.20)"
echo "   4. Ask the AI: 'Investigate the web scanner alert'"
echo "   5. Verify AI notes that source is NOT the authorized scanner (192.168.56.20)"
echo "================================================================"
