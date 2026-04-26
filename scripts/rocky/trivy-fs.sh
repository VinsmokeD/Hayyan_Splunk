#!/usr/bin/env bash
# =============================================================================
# Hayyan SOC Lab — Trivy Filesystem/Container Scanner Wrapper
# /opt/hayyan-scan/scanners/trivy-fs.sh
#
# Args: $1=RAW_DIR $2=SCAN_ID
# Scans: local filesystem + running Docker containers
# Output: $RAW_DIR/trivy-<SCAN_ID>.json
# =============================================================================
set -euo pipefail

RAW_DIR="${1:?RAW_DIR required}"
SCAN_ID="${2:?SCAN_ID required}"
CONFIG_DIR="/opt/hayyan-scan/config"
TARGETS_FILE="$CONFIG_DIR/targets.yaml"
OUTPUT_FILE="$RAW_DIR/trivy-${SCAN_ID}.json"

# ── Aggregate all Trivy findings into one JSONL file ─────────────────────────
> "$OUTPUT_FILE"  # create/empty

# Helper: run trivy and append JSON results
run_trivy_target() {
    local target_type="$1"  # "fs", "image", "rootfs"
    local target_value="$2"
    local label="$3"

    local tmp_out
    tmp_out=$(mktemp /tmp/trivy-XXXXXX.json)

    echo "[Trivy] Scanning $target_type: $target_value ..."
    trivy "$target_type" \
        --format json \
        --severity MEDIUM,HIGH,CRITICAL \
        --output "$tmp_out" \
        --quiet \
        --skip-dirs /proc,/sys,/dev \
        "$target_value" 2>/dev/null || true

    # Extract Results array and flatten to one JSON object per vulnerability
    python3 - "$tmp_out" "$target_value" "$label" <<'PYEOF'
import json, sys

tmp_out, target_value, label = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(tmp_out) as f:
        data = json.load(f)
except Exception:
    sys.exit(0)

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities") or []:
        print(json.dumps({
            "trivy_target": target_value,
            "trivy_target_label": label,
            "trivy_type": result.get("Type", ""),
            "trivy_class": result.get("Class", ""),
            "vuln_id": vuln.get("VulnerabilityID", ""),
            "pkg_name": vuln.get("PkgName", ""),
            "installed_version": vuln.get("InstalledVersion", ""),
            "fixed_version": vuln.get("FixedVersion", ""),
            "severity": vuln.get("Severity", "UNKNOWN").lower(),
            "cvss_score": (
                vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or
                vuln.get("CVSS", {}).get("nvd", {}).get("V2Score") or
                vuln.get("CVSS", {}).get("redhat", {}).get("V3Score") or 0
            ),
            "title": vuln.get("Title", ""),
            "description": (vuln.get("Description", "") or "")[:200],
            "primary_url": vuln.get("PrimaryURL", ""),
            "status": vuln.get("Status", ""),
        }))
PYEOF
    cat "$tmp_out" >> "$OUTPUT_FILE" 2>/dev/null || true
    rm -f "$tmp_out"
}

# ── Scan local filesystem ─────────────────────────────────────────────────────
run_trivy_target "fs" "/" "rocky-filesystem"

# ── Scan running Docker containers (if Docker is available) ──────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    while IFS= read -r container_id; do
        container_name=$(docker inspect --format='{{.Name}}' "$container_id" | tr -d '/')
        container_image=$(docker inspect --format='{{.Config.Image}}' "$container_id")
        echo "[Trivy] Scanning container: $container_name ($container_image)"
        run_trivy_target "image" "$container_image" "container:$container_name"
    done < <(docker ps -q)
else
    echo "[Trivy] Docker not available — skipping container scans"
fi

FINDING_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
echo "[Trivy] Wrote $FINDING_COUNT vulnerability findings to $OUTPUT_FILE"
