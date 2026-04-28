#!/usr/bin/env python3
"""
Hayyan SOC Lab — Unified Schema Normalizer
==========================================
Converts heterogeneous Nuclei and Trivy JSON output into a single
stable schema for Splunk HEC ingestion (index=vuln_scans).

Usage:
    python3 normalize.py --raw-dir /opt/hayyan-scan/logs/raw-RUN_ID \
                         --output /opt/hayyan-scan/logs/normalized-RUN_ID.jsonl \
                         --scan-id run-20260426-020000

Schema (every output record):
    time, scanid, scanner, templateid, cveid, cvssscore, severity,
    target, targetport, service, matchedat, description, remediation,
    referenceurl, trivy_pkg, trivy_installed_version, trivy_fixed_version
"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Severity normalization ────────────────────────────────────────────────────
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}

# ── Config from env ───────────────────────────────────────────────────────────
def _load_env():
    env_file = Path(__file__).parent.parent.parent / ".env"
    cfg = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                cfg[k.strip()] = v.strip()
    return {**cfg, **os.environ}

_env = _load_env()
ROCKY_IP = _env.get("ROCKY_IP", "192.168.56.20")


def normalize_nuclei_finding(raw: dict, scan_id: str, now_ts: float) -> dict:
    """Convert a single Nuclei JSON finding to the unified schema."""
    info = raw.get("info", {})
    template_id = raw.get("template-id", raw.get("templateID", ""))

    # CVE extraction from template-id or tags
    cve_id = ""
    template_lower = template_id.lower()
    if template_lower.startswith("cve-"):
        cve_id = template_id.upper()
    else:
        for tag in info.get("tags", []):
            if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                cve_id = tag.upper()
                break

    # CVSS from classification
    classification = info.get("classification", {})
    cvss_score = (
        classification.get("cvss-score") or
        classification.get("cvss_score") or
        0.0
    )
    try:
        cvss_score = float(cvss_score)
    except (ValueError, TypeError):
        cvss_score = 0.0

    # Target info
    host = raw.get("host", raw.get("ip", ""))
    matched_at = raw.get("matched-at", raw.get("matched_at", host))
    port = ""
    if ":" in matched_at:
        parts = matched_at.split(":")
        try:
            port = parts[-1].split("/")[0]
        except Exception:
            port = ""

    # Service detection from matched URL
    service = "http"
    if matched_at.startswith("https://"):
        service = "https"
    elif matched_at.startswith("ftp://"):
        service = "ftp"
    elif ":" in matched_at and not matched_at.startswith("http"):
        service = "tcp"

    severity = SEVERITY_MAP.get(info.get("severity", "low"), "low")

    refs = info.get("reference", [])
    if isinstance(refs, str):
        refs = [refs]
    reference_url = refs[0] if refs else ""

    return {
        "time": now_ts,
        "scanid": scan_id,
        "scanner": "nuclei",
        "templateid": template_id,
        "cveid": cve_id,
        "cvssscore": cvss_score,
        "severity": severity,
        "target": host,
        "targetport": port,
        "service": service,
        "matchedat": matched_at,
        "description": (info.get("description", info.get("name", ""))[:250]),
        "remediation": (info.get("remediation", "")[:250]),
        "referenceurl": reference_url,
        "trivy_pkg": "",
        "trivy_installed_version": "",
        "trivy_fixed_version": "",
        "scanner_host": ROCKY_IP,
    }


def normalize_trivy_finding(raw: dict, scan_id: str, now_ts: float) -> dict:
    """Convert a single Trivy JSON finding (flattened) to the unified schema."""
    vuln_id = raw.get("vuln_id", "")
    cve_id = vuln_id if vuln_id.upper().startswith("CVE-") else ""
    severity = SEVERITY_MAP.get(raw.get("severity", "unknown"), "low")

    cvss_score = raw.get("cvss_score", 0.0)
    try:
        cvss_score = float(cvss_score)
    except (ValueError, TypeError):
        cvss_score = 0.0

    target = raw.get("trivy_target", ROCKY_IP)
    # For container images, target = the image name; for FS, it's the host
    if target == "/" or target.startswith("/"):
        target = ROCKY_IP

    pkg = raw.get("pkg_name", "")
    fixed_ver = raw.get("fixed_version", "")
    remediation = ""
    if fixed_ver:
        remediation = f"Upgrade {pkg} to version {fixed_ver}"
    elif pkg:
        remediation = f"Check vendor advisory for {pkg}"

    return {
        "time": now_ts,
        "scanid": scan_id,
        "scanner": "trivy",
        "templateid": vuln_id,
        "cveid": cve_id,
        "cvssscore": cvss_score,
        "severity": severity,
        "target": target,
        "targetport": "",
        "service": raw.get("trivy_type", "os-pkgs"),
        "matchedat": raw.get("trivy_target_label", target),
        "description": raw.get("title", raw.get("description", ""))[:250],
        "remediation": remediation[:250],
        "referenceurl": raw.get("primary_url", ""),
        "trivy_pkg": pkg,
        "trivy_installed_version": raw.get("installed_version", ""),
        "trivy_fixed_version": fixed_ver,
        "scanner_host": ROCKY_IP,
    }


def process_nuclei_file(filepath: Path, scan_id: str, now_ts: float) -> list[dict]:
    """Parse a Nuclei JSON export (one JSON object per line)."""
    records = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                if isinstance(raw, dict):
                    records.append(normalize_nuclei_finding(raw, scan_id, now_ts))
                elif isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict):
                            records.append(normalize_nuclei_finding(item, scan_id, now_ts))
                else:
                    log.warning("Unexpected Nuclei JSON type at %s line %d: %s", filepath.name, line_num, type(raw).__name__)
            except json.JSONDecodeError as e:
                log.warning("Nuclei parse error at %s line %d: %s", filepath.name, line_num, e)
    return records


def process_trivy_file(filepath: Path, scan_id: str, now_ts: float) -> list[dict]:
    """Parse a Trivy flattened JSONL file."""
    records = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                if isinstance(raw, dict):
                    records.append(normalize_trivy_finding(raw, scan_id, now_ts))
                elif isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict):
                            records.append(normalize_trivy_finding(item, scan_id, now_ts))
                else:
                    log.warning("Unexpected Trivy JSON type at %s line %d: %s", filepath.name, line_num, type(raw).__name__)
            except json.JSONDecodeError as e:
                log.warning("Trivy parse error at %s line %d: %s", filepath.name, line_num, e)
    return records


def main():
    parser = argparse.ArgumentParser(description="Normalize Nuclei/Trivy scan output to unified schema")
    parser.add_argument("--raw-dir", required=True, help="Directory containing raw scanner output files")
    parser.add_argument("--output", required=True, help="Output JSONL file path")
    parser.add_argument("--scan-id", required=True, help="Scan run identifier")
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    output = Path(args.output)
    scan_id = args.scan_id
    now_ts = time.time()

    if not raw_dir.is_dir():
        log.error("raw-dir not found: %s", raw_dir)
        sys.exit(1)

    all_records: list[dict] = []

    # Process Nuclei files
    for filepath in raw_dir.glob("nuclei-*.json"):
        log.info("Processing Nuclei file: %s", filepath.name)
        records = process_nuclei_file(filepath, scan_id, now_ts)
        log.info("  → %d Nuclei findings", len(records))
        all_records.extend(records)

    # Process Trivy files
    for filepath in raw_dir.glob("trivy-*.json"):
        log.info("Processing Trivy file: %s", filepath.name)
        records = process_trivy_file(filepath, scan_id, now_ts)
        log.info("  → %d Trivy findings", len(records))
        all_records.extend(records)

    if not all_records:
        log.info("No findings to normalize.")
        output.write_text("")
        return

    # Write output JSONL
    with open(output, "w", encoding="utf-8") as f:
        for record in all_records:
            f.write(json.dumps(record) + "\n")

    log.info("Normalized %d total findings → %s", len(all_records), output)

    # Summary by severity
    from collections import Counter
    sev_counts = Counter(r["severity"] for r in all_records)
    log.info("Severity breakdown: %s", dict(sev_counts))

    # Summary by scanner
    scanner_counts = Counter(r["scanner"] for r in all_records)
    log.info("Scanner breakdown: %s", dict(scanner_counts))


if __name__ == "__main__":
    main()
