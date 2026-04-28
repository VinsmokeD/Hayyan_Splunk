#!/usr/bin/env python3
"""
Hayyan SOC Lab - Critical Findings to MISP Mirroring.

Reads normalized JSONL and creates MISP events for findings above the CVSS
threshold only when MISP_ALLOW_WRITE=true. The default is draft-only/no-write
behavior so vulnerability scan validation cannot publish intelligence by
accident.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _load_env() -> dict[str, str]:
    scan_home = Path(__file__).resolve().parent.parent
    env_files = [
        scan_home / "config" / "splunkhec.env",
        scan_home / ".env",
        Path("/opt/.env"),
    ]
    cfg: dict[str, str] = {}
    for env_file in env_files:
        if not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                cfg[key.strip()] = value.strip()
    return {**cfg, **os.environ}


_env = _load_env()

MISP_URL = _env.get("MISP_URL", "https://127.0.0.1:8443").rstrip("/")
MISP_API_KEY = _env.get("MISP_API_KEY", "")
MISP_ALLOW_WRITE = _env.get("MISP_ALLOW_WRITE", "false").lower() == "true"

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
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        log.error("MISP HTTP %s for %s: %s", exc.code, path, body[:200])
        return {}
    except Exception as exc:
        log.error("MISP request failed for %s: %s", path, exc)
        return {}


def create_misp_vuln_event(finding: dict, scan_id: str) -> bool:
    """Create a MISP event for one high-value vulnerability finding."""
    cve_id = finding.get("cveid", "")
    target = finding.get("target", "unknown")
    severity = finding.get("severity", "high")
    cvss = finding.get("cvssscore", 0.0)
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    scanner = finding.get("scanner", "scanner")
    service = finding.get("service", "")
    template_id = finding.get("templateid", "")
    ref_url = finding.get("referenceurl", "")

    title = f"[{severity.upper()}] {cve_id or template_id} on {target} - Hayyan Lab Scan {scan_id}"
    attributes = []

    if target:
        is_ip = all(char.isdigit() or char == "." for char in target)
        attributes.append(
            {
                "type": "ip-dst" if is_ip else "hostname",
                "value": target,
                "category": "Network activity",
                "to_ids": False,
                "comment": f"Vulnerable host detected by {scanner}",
                "distribution": 0,
            }
        )

    if cve_id:
        attributes.append(
            {
                "type": "vulnerability",
                "value": cve_id,
                "category": "External analysis",
                "to_ids": False,
                "comment": f"CVSS: {cvss} - Service: {service}",
                "distribution": 0,
            }
        )

    if ref_url:
        attributes.append(
            {
                "type": "url",
                "value": ref_url,
                "category": "External analysis",
                "to_ids": False,
                "comment": "Vulnerability reference",
                "distribution": 0,
            }
        )

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
    attributes.append(
        {
            "type": "comment",
            "value": full_description[:2000],
            "category": "Other",
            "to_ids": False,
            "distribution": 0,
        }
    )

    payload = {
        "Event": {
            "info": title,
            "distribution": 0,
            "threat_level_id": 3,
            "analysis": 0,
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
    event_id = result.get("Event", {}).get("id")
    if event_id:
        log.info("MISP event #%s created: %s", event_id, title[:80])
        return True
    log.warning("MISP event creation failed for: %s", title[:80])
    return False


def group_by_target_cve(records: list[dict], min_cvss: float) -> list[dict]:
    """Deduplicate findings by target and CVE/template."""
    seen = set()
    result = []
    for rec in sorted(records, key=lambda item: item.get("cvssscore", 0), reverse=True):
        if float(rec.get("cvssscore", 0)) < min_cvss:
            continue
        key = (rec.get("target", ""), rec.get("cveid", "") or rec.get("templateid", ""))
        if key not in seen:
            seen.add(key)
            result.append(rec)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Mirror critical vulnerability findings to MISP")
    parser.add_argument("--input", required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--min-cvss", type=float, default=7.0)
    args = parser.parse_args()

    if not MISP_API_KEY:
        log.warning("MISP_API_KEY not set - skipping MISP mirroring.")
        return

    if not MISP_ALLOW_WRITE:
        log.info("MISP_ALLOW_WRITE=false - scanner findings will not be written to MISP automatically.")
        return

    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input not found: %s", input_path)
        sys.exit(1)

    records = []
    with open(input_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    candidates = group_by_target_cve(records, args.min_cvss)
    log.info("Found %d unique findings with CVSS >= %.1f to mirror to MISP.", len(candidates), args.min_cvss)
    if not candidates:
        log.info("Nothing above threshold - no MISP events to create.")
        return

    created = 0
    for finding in candidates[:10]:
        if create_misp_vuln_event(finding, args.scan_id):
            created += 1
        time.sleep(0.5)

    log.info("MISP mirroring complete: %d/%d events created.", created, len(candidates))


if __name__ == "__main__":
    main()
