#!/usr/bin/env python3
"""
Push high/critical vulnerability findings to MISP as threat intelligence events.

Only creates MISP events for findings with CVSS >= min_cvss (default 7.0).
Groups all findings from a single scan into one MISP event per target host
to avoid flooding MISP with individual CVE events.
"""
import argparse
import json
import logging
import sys
from collections import defaultdict
from typing import Iterator

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


def iter_findings(path: str) -> Iterator[dict]:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass


def misp_headers(key: str) -> dict:
    return {
        "Authorization": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def create_misp_event(
    misp_url: str,
    misp_key: str,
    scan_id: str,
    target: str,
    findings: list[dict],
) -> bool:
    """Create one MISP event grouping all findings for a given target host."""
    cves = sorted({f["cve_id"] for f in findings if f.get("cve_id")})
    max_cvss = max((f.get("cvss_score", 0) for f in findings), default=0)
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")

    title = (
        f"Hayyan-Internal Vuln Scan — {target} — "
        f"{critical_count} critical, {high_count} high ({scan_id})"
    )

    # Build description
    desc_lines = [
        f"Automated vulnerability scan by Hayyan SOC Lab scanner ({scan_id}).",
        f"Target: {target}",
        f"Max CVSS: {max_cvss}",
        f"Critical findings: {critical_count}, High findings: {high_count}",
        "",
        "Findings summary:",
    ]
    for f in sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)[:20]:
        desc_lines.append(
            f"  [{f['severity'].upper()}] {f.get('cve_id') or f.get('template_id')} "
            f"(CVSS {f.get('cvss_score',0)}) — {f.get('service','')} — {f.get('remediation','')}"
        )

    attributes = [
        {
            "type": "comment",
            "value": "\n".join(desc_lines),
            "category": "Other",
            "to_ids": False,
            "distribution": 0,
        },
        {
            "type": "ip-dst",
            "value": target,
            "category": "Network activity",
            "to_ids": False,
            "distribution": 0,
            "comment": "Scanned host",
        },
    ]

    # Add CVE attributes
    for cve in cves[:50]:
        attributes.append({
            "type": "vulnerability",
            "value": cve,
            "category": "External analysis",
            "to_ids": False,
            "distribution": 0,
        })

    event_payload = {
        "Event": {
            "info": title,
            "distribution": 0,     # Your organisation only
            "threat_level_id": 2,  # Medium
            "analysis": 0,         # Initial
            "Tag": [
                {"name": "tlp:amber"},
                {"name": "origin:hayyan-internal"},
                {"name": "source:vulnerability-scanner"},
                {"name": f"scan-id:{scan_id}"},
            ],
            "Attribute": attributes,
        }
    }

    try:
        resp = requests.post(
            f"{misp_url.rstrip('/')}/events",
            headers=misp_headers(misp_key),
            json=event_payload,
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        event_id = resp.json().get("Event", {}).get("id", "?")
        print(f"[push_misp] Created MISP event #{event_id} for {target} ({len(findings)} findings)")
        return True
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to MISP at %s", misp_url)
        return False
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else 0
        if status == 403:
            log.error("MISP API key rejected (403). Check MISP_API_KEY in splunk_hec.env")
        else:
            log.error("MISP HTTP error %s: %s", status, e)
        return False
    except Exception as e:
        log.error("MISP push error: %s", e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Push vulnerability findings to MISP")
    parser.add_argument("--normalized", required=True)
    parser.add_argument("--misp-url", default="https://192.168.56.1:8443")
    parser.add_argument("--misp-key", default="")
    parser.add_argument("--min-cvss", type=float, default=7.0)
    args = parser.parse_args()

    if not args.misp_key:
        print("[push_misp] WARN: No MISP_API_KEY set — skipping MISP push")
        return

    # Group qualifying findings by target host
    by_target: dict[str, list[dict]] = defaultdict(list)
    scan_id = ""
    skipped = 0

    for finding in iter_findings(args.normalized):
        scan_id = finding.get("scan_id", scan_id)
        cvss = float(finding.get("cvss_score", 0))
        if cvss >= args.min_cvss:
            by_target[finding.get("target", "unknown")].append(finding)
        else:
            skipped += 1

    if not by_target:
        print(f"[push_misp] No findings with CVSS >= {args.min_cvss} — nothing to push")
        return

    print(f"[push_misp] Pushing {sum(len(v) for v in by_target.values())} findings "
          f"across {len(by_target)} host(s) to MISP (skipped {skipped} below threshold)")

    created = 0
    for target, findings in by_target.items():
        if create_misp_event(args.misp_url, args.misp_key, scan_id, target, findings):
            created += 1

    print(f"[push_misp] {created}/{len(by_target)} MISP event(s) created")
    if created < len(by_target):
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
