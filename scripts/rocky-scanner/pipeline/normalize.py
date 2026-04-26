#!/usr/bin/env python3
"""
Normalize Nuclei and Trivy JSON output into the unified vuln_scans schema.

Unified schema (one JSON object per line — JSONL output):
{
  "time": 1745480000,         # Unix timestamp of the scan
  "scan_id": "20260424-0230",
  "scanner": "nuclei|trivy",
  "template_id": "CVE-2024-1234",
  "cve_id": "CVE-2024-1234",  # empty string if no CVE
  "cvss_score": 8.1,
  "severity": "high",
  "target": "192.168.56.20",
  "target_port": 443,
  "service": "nginx",
  "matched_at": "https://192.168.56.20/admin",
  "description": "...",
  "tags": ["nginx","cve","2024"],
  "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
  "remediation": "Upgrade nginx to 1.25.4"
}
"""
import argparse
import glob
import json
import logging
import os
import re
import time
from datetime import datetime

log = logging.getLogger(__name__)


SEV_CVSS_DEFAULTS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
    "unknown": 0.0,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve(text: str) -> str:
    """Return the first CVE ID found in text, or empty string."""
    if not text:
        return ""
    m = CVE_RE.search(text)
    return m.group(0).upper() if m else ""


# ── Nuclei normalizer ─────────────────────────────────────────────────────────

def normalize_nuclei(raw_file: str, scan_id: str, scan_ts: int) -> list[dict]:
    findings = []
    if not os.path.exists(raw_file) or os.path.getsize(raw_file) == 0:
        return findings

    with open(raw_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = r.get("info", {})
            severity = (r.get("info", {}).get("severity") or "unknown").lower()

            # Extract CVE from template ID or tags
            template_id = r.get("template-id", "")
            cve_id = extract_cve(template_id)
            if not cve_id:
                for tag in info.get("tags", []):
                    cve_id = extract_cve(tag)
                    if cve_id:
                        break

            # CVSS score — prefer explicit, fall back to severity default
            cvss_score = float(
                info.get("classification", {}).get("cvss-score")
                or SEV_CVSS_DEFAULTS.get(severity, 0.0)
            )

            # Parse target and port from matched-at URL
            matched_at = r.get("matched-at", "")
            target = r.get("host", "")
            port = 0
            try:
                from urllib.parse import urlparse
                parsed = urlparse(matched_at or target)
                if parsed.hostname:
                    target = parsed.hostname
                if parsed.port:
                    port = parsed.port
                elif parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80
            except Exception:
                pass

            # Infer service from tags + port
            tags = info.get("tags", [])
            service = next(
                (t for t in tags if t in (
                    "nginx", "apache", "iis", "rdp", "smb", "ldap",
                    "ssh", "ftp", "http", "https", "ssl", "tls", "kerberos",
                )),
                f"port-{port}" if port else "unknown",
            )

            refs = info.get("reference", [])
            ref_url = refs[0] if refs else (
                f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
            )

            remediation = (
                info.get("remediation")
                or (f"Patch/update the affected service ({service})" if service else "Review vendor advisory")
            )

            findings.append({
                "time": scan_ts,
                "scan_id": scan_id,
                "scanner": "nuclei",
                "template_id": template_id,
                "cve_id": cve_id,
                "cvss_score": round(cvss_score, 1),
                "severity": severity,
                "target": target,
                "target_port": port,
                "service": service,
                "matched_at": matched_at,
                "description": info.get("description", info.get("name", "")),
                "tags": tags,
                "reference_url": ref_url,
                "remediation": remediation,
            })

    return findings


# ── Trivy normalizer ──────────────────────────────────────────────────────────

def normalize_trivy(raw_file: str, scan_id: str, scan_ts: int, target_override: str = "") -> list[dict]:
    findings = []
    if not os.path.exists(raw_file) or os.path.getsize(raw_file) == 0:
        return findings

    with open(raw_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            log.warning("Malformed Trivy JSON: %s", raw_file)
            return findings

    art_name = data.get("ArtifactName", target_override or "unknown")
    target = target_override or art_name

    for result in data.get("Results", []):
        service = result.get("Type", "filesystem")  # e.g. "rpm", "node-pkg"
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").lower()

            # CVSS — prefer V3 over V2
            cvss_score = 0.0
            cvss_data = vuln.get("CVSS", {})
            for source in ("nvd", "redhat", "ghsa"):
                v3 = cvss_data.get(source, {}).get("V3Score")
                if v3:
                    cvss_score = float(v3)
                    break
            if not cvss_score:
                cvss_score = SEV_CVSS_DEFAULTS.get(severity, 0.0)

            cve_id = vuln.get("VulnerabilityID", "")
            refs = vuln.get("References", [])
            nvd_url = next((r for r in refs if "nvd.nist.gov" in r), refs[0] if refs else "")

            fixed_ver = vuln.get("FixedVersion", "")
            installed_ver = vuln.get("InstalledVersion", "")
            pkg_name = vuln.get("PkgName", "")
            remediation = (
                f"Upgrade {pkg_name} from {installed_ver} to {fixed_ver}"
                if fixed_ver else
                f"No fix available yet for {pkg_name} {installed_ver} — monitor vendor advisory"
            )

            findings.append({
                "time": scan_ts,
                "scan_id": scan_id,
                "scanner": "trivy",
                "template_id": f"trivy-{cve_id}" if cve_id else f"trivy-{pkg_name}",
                "cve_id": cve_id,
                "cvss_score": round(cvss_score, 1),
                "severity": severity,
                "target": target,
                "target_port": 0,
                "service": service,
                "matched_at": f"{target}/{pkg_name}@{installed_ver}",
                "description": vuln.get("Description", vuln.get("Title", "")),
                "tags": ["trivy", service, severity],
                "reference_url": nvd_url,
                "remediation": remediation,
            })

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Normalize scan results to unified schema")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    scan_ts = int(time.time())
    all_findings: list[dict] = []

    # Nuclei web scan
    nuclei_web = os.path.join(args.raw_dir, f"nuclei_web-{args.scan_id}.json")
    all_findings.extend(normalize_nuclei(nuclei_web, args.scan_id, scan_ts))

    # Nuclei DC01 scan
    nuclei_dc01 = os.path.join(args.raw_dir, f"nuclei_dc01-{args.scan_id}.json")
    all_findings.extend(normalize_nuclei(nuclei_dc01, args.scan_id, scan_ts))

    # Trivy filesystem
    trivy_fs = os.path.join(args.raw_dir, f"trivy_fs-{args.scan_id}.json")
    all_findings.extend(normalize_trivy(trivy_fs, args.scan_id, scan_ts, target_override="192.168.56.20"))

    # Any extra trivy image scans dropped in raw_dir
    for img_file in glob.glob(os.path.join(args.raw_dir, f"trivy_img_*-{args.scan_id}.json")):
        # Infer target from filename: trivy_img_splunk__splunk__latest-SCANID.json
        base = os.path.basename(img_file).replace(f"-{args.scan_id}.json", "").replace("trivy_img_", "")
        all_findings.extend(normalize_trivy(img_file, args.scan_id, scan_ts, target_override=base))

    with open(args.output, "w") as out:
        for finding in all_findings:
            out.write(json.dumps(finding) + "\n")

    print(f"[normalize] {len(all_findings)} findings written to {args.output}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
