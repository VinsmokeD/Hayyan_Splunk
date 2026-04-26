#!/usr/bin/env bash
# Trivy — filesystem scan of Rocky Linux rootfs + Docker container images
# Scans for CVEs in installed RPM packages and container layers
# Called by orchestrator.sh with: SCAN_ID RAW_DIR

set -euo pipefail

SCAN_ID="${1:?SCAN_ID required}"
RAW_DIR="${2:?RAW_DIR required}"

FS_OUTPUT="$RAW_DIR/trivy_fs-$SCAN_ID.json"
CONTAINERS_OUTPUT="$RAW_DIR/trivy_containers-$SCAN_ID.json"

# ── Filesystem scan (Rocky Linux RPM packages) ────────────────────────────────
echo "[trivy_fs] Scanning Rocky Linux rootfs..."

trivy filesystem / \
    --severity HIGH,CRITICAL \
    --skip-dirs /proc,/sys,/dev,/run,/opt/hayyan-scan/.venv,/home \
    --format json \
    --output "$FS_OUTPUT" \
    --quiet \
    --timeout 5m0s \
    2>/dev/null || echo "[trivy_fs] WARN: trivy fs returned non-zero (partial results saved)"

FS_COUNT=$(python3 -c "
import json, sys
try:
    d=json.load(open('$FS_OUTPUT'))
    vulns=[v for r in d.get('Results',[]) for v in r.get('Vulnerabilities',[])]
    print(len(vulns))
except:
    print(0)
" 2>/dev/null || echo 0)
echo "[trivy_fs] Filesystem scan done — $FS_COUNT vulnerabilities"

# ── Container image scans (Splunk + MISP running on host) ────────────────────
# These use the Docker socket exposed via SSH — requires ssh key auth to host
HOST_IP="192.168.56.1"
IMAGES=("splunk/splunk:latest" "coolacid/misp-docker:core-latest")

echo "[]" > "$CONTAINERS_OUTPUT"   # valid empty array as fallback

if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@"$HOST_IP" "command -v docker" &>/dev/null; then
    echo "[trivy_fs] Docker accessible on host — scanning container images..."
    COMBINED="[]"
    for IMAGE in "${IMAGES[@]}"; do
        TMP="$RAW_DIR/trivy_img_$(echo "$IMAGE" | tr '/:' '__')-$SCAN_ID.json"
        ssh -o ConnectTimeout=10 root@"$HOST_IP" \
            "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
             aquasec/trivy:latest image --severity HIGH,CRITICAL \
             --format json --quiet $IMAGE" > "$TMP" 2>/dev/null || true

        IMG_COUNT=$(python3 -c "
import json, sys
try:
    d=json.load(open('$TMP'))
    vulns=[v for r in d.get('Results',[]) for v in r.get('Vulnerabilities',[])]
    print(len(vulns))
except:
    print(0)
" 2>/dev/null || echo 0)
        echo "[trivy_fs] Image $IMAGE — $IMG_COUNT vulnerabilities"
    done
    echo "[trivy_fs] Container scan done"
else
    echo "[trivy_fs] WARN: Cannot reach Docker on host ($HOST_IP) — skipping container scan"
fi
