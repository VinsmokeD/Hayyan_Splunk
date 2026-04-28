#!/usr/bin/env python3
"""
Hayyan SOC Lab — Critical Findings → MISP Mirroring
=====================================================
Reads normalized JSONL and creates MISP events for findings above the
CVSS threshold. Closes the feedback loop: discovered vulnerabilities
become threat intelligence entries that the AI agent can reason about.

Usage:
    python3 push_misp.py --input normalized.jsonl \
                         --scan-id run-20260426 \
                         --min-cvss 7.0
"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error
import ssl

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
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

MISP_URL = _env.get("MISP_URL", "https://127.0.0.1:8443").rstrip("/")
MISP_API_KEY = _env.get("MISP_API_KEY", "")

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _misp_request(path: str, payload: dict) -> dict:
    url = f"{MISP_URL}{path}"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error("MISP HTTP %s for %s: %s", e.code, path, body[:200])
        return {}
    except Exception as e:
        log.error("MISP request failed for %s: %s", path, e)
        return {}


def create_misp_vuln_event(finding: dict, scan_id: str) -> bool:
    """Create a MISP event for a critical/high vulnerability finding."""
    cve_id = finding.get("cveid", "")
    target = finding.get("target", "unknown")
    severity = finding.get("severity", "high")
    cvss = finding.get("cvssscore", 0.0)
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    scanner = finding.get("scanner", "nuclei")
    service = finding.get("service", "")
    template_id = finding.get("templateid", "")
    ref_url = finding.get("referenceurl", "")

    title = f"[{severity.upper()}] {cve_id or template_id} on {target} — Hayyan Lab Scan {scan_id}"

    attributes = []

    # Host attribute
    if target:
        is_ip = all(c.isdigit() or c == "." for c in target)
        attributes.append({
            "type": "ip-dst" if is_ip else "hostname",
            "value": target,
            "category": "Network activity",
            "to_ids": False,
            "comment": f"Vulnerable host — detected by {scanner}",
            "distribution": 0,
        })

    # CVE attribute
    if cve_id:
        attributes.append({
            "type": "vulnerability",
            "value": cve_id,
            "category": "External analysis",
            "to_ids": False,
            "comment": f"CVSS: {cvss} — Service: {service}",
            "distribution": 0,
        })

    # Reference URL
    if ref_url:
        attributes.append({
            "type": "url",
            "value": ref_url,
            "category": "External analysis",
            "to_ids": False,
            "comment": "Vulnerability reference",
            "distribution": 0,
        })

    # Description as comment
    full_description = (
        f"Hayyan SOC Lab automated scan ({scanner})\n"
        f"Scan ID: {scan_id}\n"
        f"Target: {target}\n"
        f"Service: {service}\n"
        f"CVSS Score: {cvss}\n"
        f"Template: {template_id}\n\n"
        f"Description: {description}\n\n"
        f"Remediation: {remediation}"
    )
    attributes.append({
        "type": "comment",
        "value": full_description[:2000],
        "category": "Other",
        "to_ids": False,
        "distribution": 0,
    })

    payload = {
        "Event": {
            "info": title,
            "distribution": 0,       # Your organisation only
            "threat_level_id": 3,    # 3 = Low (it's exposure, not active exploit)
            "analysis": 0,            # 0 = Initial
            "Tag": [
                {"name": "tlp:amber"},
                {"name": "origin:hayyan-internal"},
                {"name": f"source:scanner:{scanner}"},
                {"name": f"severity:{severity}"},
                {"name": "type:vulnerability"},
            ],
            "Attribute": attributes,
        }
    }

    result = _misp_request("/events", payload)
    if result.get("Event", {}).get("id"):
        event_id = result["Event"]["id"]
        log.info("MISP event #%s created: %s", event_id, title[:80])
        return True
    else:
        log.warning("MISP event creation failed for: %s", title[:80])
        return False


def group_by_target_cve(records: list[dict], min_cvss: float) -> list[dict]:
    """Deduplicate findings by (target, cve_id) — only one MISP event per unique vulnerability."""
    seen = set()
    result = []
    for rec in sorted(records, key=lambda r: r.get("cvssscore", 0), reverse=True):
        if float(rec.get("cvssscore", 0)) < min_cvss:
            continue
        key = (rec.get("target", ""), rec.get("cveid", "") or rec.get("templateid", ""))
        if key not in seen:
            seen.add(key)
            result.append(rec)
    return result


def main():
    parser = argparse.ArgumentParser(description="Mirror critical vulnerability findings to MISP")
    parser.add_argument("--input", required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--min-cvss", type=float, default=7.0)
    args = parser.parse_args()

    if not MISP_API_KEY:
        log.warning("MISP_API_KEY not set — skipping MISP mirroring")
        return

    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input not found: %s", input_path)
        sys.exit(1)

    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    candidates = group_by_target_cve(records, args.min_cvss)
    log.info("Found %d unique critical/high findings (CVSS >= %.1f) to mirror to MISP", len(candidates), args.min_cvss)

    if not candidates:
        log.info("Nothing above threshold — no MISP events to create.")
        return

    # Rate-limit MISP event creation
    created = 0
    for finding in candidates[:10]:  # Cap at 10 events per scan run
        if create_misp_vuln_event(finding, args.scan_id):
            created += 1
        time.sleep(0.5)  # Be gentle with MISP API

    log.info("MISP mirroring complete: %d/%d events created", created, len(candidates))


if __name__ == "__main__":
    main()
