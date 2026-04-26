#!/usr/bin/env bash
# Nuclei — Windows Server 2022 / DC01 network scan
# Targets DC01 SMB (445), RDP (3389), LDAP (389/636), WinRM (5985), HTTP (80/443)
# Called by orchestrator.sh with: SCAN_ID RAW_DIR

set -euo pipefail

SCAN_ID="${1:?SCAN_ID required}"
RAW_DIR="${2:?RAW_DIR required}"

OUTPUT="$RAW_DIR/nuclei_dc01-$SCAN_ID.json"
DC01_IP="192.168.56.10"

echo "[nuclei_dc01] Scanning DC01 at $DC01_IP (SMB/RDP/LDAP/WinRM)..."

# Check DC01 is reachable first — avoid long timeout if VM is down
if ! ping -c1 -W2 "$DC01_IP" &>/dev/null; then
    echo "[nuclei_dc01] WARN: DC01 ($DC01_IP) unreachable, skipping scan"
    touch "$OUTPUT"
    exit 0
fi

nuclei \
    -targets "$DC01_IP" \
    -severity medium,high,critical \
    -tags "smb,rdp,ldap,windows,kerberos,ssl,network" \
    -exclude-tags "dos,fuzz,helpers,web-cache-deception" \
    -rate-limit 15 \
    -timeout 8 \
    -retries 1 \
    -json \
    -output "$OUTPUT" \
    -silent \
    -no-color \
    2>&1 | grep -v "^\[" || true

COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
echo "[nuclei_dc01] Done — $COUNT findings → $OUTPUT"
