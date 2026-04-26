"""
MISP + Vulnerability Posture tools — Task 2 additions.

Three tools bolted onto the existing ReAct agent:
  - query_misp_ioc      : Look up an indicator in MISP threat intel
  - get_vuln_posture    : Query vuln_scans index for open CVEs per host
  - create_misp_event   : Write a confirmed incident back into MISP (HITL)
"""
import json
import logging
from typing import Optional

import requests
import urllib3

from langchain_core.tools import tool
from ..core.config import get_settings
from .audit_tools import audit_tool_call

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


def _misp_headers() -> dict:
    cfg = get_settings()
    return {
        "Authorization": cfg.misp_api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _misp_verify() -> bool:
    return get_settings().misp_verify_ssl


def _misp_base() -> str:
    return get_settings().misp_url.rstrip("/")


# ── Tool 1: query_misp_ioc ────────────────────────────────────────────────────

@tool
def query_misp_ioc(indicator: str) -> str:
    """
    Look up an indicator of compromise (IP, domain, hash, URL) in the MISP
    threat intelligence platform. Returns whether the indicator is known-bad,
    which threat events reference it, tags, and first/last seen timestamps.

    Call this whenever you find a suspicious IP, domain, file hash, or URL
    during an investigation. A MISP hit elevates confidence and severity.

    Args:
        indicator: The IoC to search — IP address, domain, MD5/SHA256 hash, or URL.
                   Examples: "185.220.101.45", "evil.example.com",
                             "d41d8cd98f00b204e9800998ecf8427e"
    """
    with audit_tool_call("query_misp_ioc", {"indicator": indicator}):
        cfg = get_settings()
        if not cfg.misp_api_key:
            return json.dumps({
                "found": False,
                "error": "MISP_API_KEY not configured. Add it to .env and restart.",
                "note": "Deploy MISP: docker compose -f docker-compose.misp.yml up -d",
            })

        try:
            url = f"{_misp_base()}/attributes/restSearch"
            payload = {
                "returnFormat": "json",
                "value": indicator,
                "limit": 20,
                "includeEventUuid": True,
                "includeEventTags": True,
            }
            resp = requests.post(
                url,
                headers=_misp_headers(),
                json=payload,
                verify=_misp_verify(),
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return json.dumps({
                    "found": False,
                    "indicator": indicator,
                    "message": "No MISP intelligence found for this indicator.",
                })

            # Aggregate across matching attributes
            events: list[dict] = []
            tags: set[str] = set()
            timestamps: list[int] = []

            for attr in attrs:
                event_info = attr.get("Event", {}).get("info", "Unknown event")
                event_uuid = attr.get("event_uuid", "")
                attr_tags = [t.get("name", "") for t in attr.get("Tag", [])]
                tags.update(attr_tags)

                ts = int(attr.get("timestamp", 0))
                if ts:
                    timestamps.append(ts)

                events.append({
                    "event_info": event_info,
                    "event_uuid": event_uuid,
                    "attribute_type": attr.get("type", ""),
                    "tags": attr_tags,
                })

            result = {
                "found": True,
                "indicator": indicator,
                "match_count": len(attrs),
                "events": events[:10],  # cap to 10 for token budget
                "all_tags": sorted(tags),
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "confidence": "high" if len(attrs) >= 3 else "medium" if len(attrs) >= 1 else "low",
                "recommendation": (
                    "KNOWN MALICIOUS — Escalate immediately. This indicator appears in "
                    f"{len(attrs)} MISP event(s)."
                ),
            }
            return json.dumps(result, indent=2)

        except requests.exceptions.ConnectionError:
            return json.dumps({
                "found": False,
                "error": f"Cannot connect to MISP at {_misp_base()}. Is it running?",
                "start_cmd": "docker compose -f docker-compose.misp.yml up -d",
            })
        except requests.exceptions.Timeout:
            return json.dumps({"found": False, "error": "MISP request timed out (10s)."})
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                return json.dumps({"found": False, "error": "MISP API key invalid or expired."})
            return json.dumps({"found": False, "error": f"MISP HTTP error: {e}"})
        except Exception as e:
            log.exception("query_misp_ioc failed")
            return json.dumps({"found": False, "error": str(e)})


# ── Tool 2: get_vuln_posture ──────────────────────────────────────────────────

@tool
def get_vuln_posture(target: Optional[str] = None, min_severity: str = "medium") -> str:
    """
    Query the vuln_scans Splunk index for open CVEs and vulnerability findings
    across lab hosts. Returns findings grouped by severity with remediation advice.

    Call this when triaging an alert on a specific host — unpatched vulnerabilities
    change the risk calculus significantly. A host with open critical CVEs that is
    being actively attacked is a crown-jewel situation.

    Args:
        target: Host to query — IP or hostname (e.g. "192.168.56.20", "DC01").
                Leave empty to get posture for ALL lab hosts.
        min_severity: Minimum severity to include: "low", "medium", "high", "critical".
                      Default "medium" filters out informational noise.
    """
    with audit_tool_call("get_vuln_posture", {"target": target, "min_severity": min_severity}):
        from ..core.splunk_client import SplunkClient
        from .spl_guardrails import validate_spl

        sev_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        sev_order = sev_map.get(min_severity.lower(), 1)
        sev_filter = " OR ".join(
            f'severity="{s}"' for s, v in sev_map.items() if v >= sev_order
        )

        target_filter = f'target="{target}"' if target else ""
        where_clause = " ".join(filter(None, [target_filter, f"({sev_filter})"]))

        spl = (
            f'index=vuln_scans {where_clause} '
            f'| stats count as finding_count, '
            f'  values(cve_id) as cves, '
            f'  max(cvss_score) as max_cvss, '
            f'  values(remediation) as remediations '
            f'  by target, severity, service '
            f'| sort -max_cvss'
        )

        ok, reason = validate_spl(spl)
        if not ok:
            return f"SPL validation failed: {reason}"

        try:
            client = SplunkClient()
            results = client.run_search(spl, earliest="-30d", max_results=100)

            if not results:
                scope = f"for {target}" if target else "for all hosts"
                return json.dumps({
                    "status": "clean",
                    "message": (
                        f"No {min_severity}+ severity findings {scope} in the last 30 days. "
                        "Either no scans have run yet or the host is well-patched. "
                        "Run the scanner: ssh rocky@192.168.56.20 "
                        "sudo /opt/hayyan-scan/orchestrator.sh"
                    ),
                    "spl_used": spl,
                })

            # Aggregate summary
            host_totals: dict[str, dict] = {}
            for row in results:
                tgt = row.get("target", "unknown")
                if tgt not in host_totals:
                    host_totals[tgt] = {
                        "target": tgt,
                        "findings": [],
                        "max_cvss": 0.0,
                        "critical_count": 0,
                        "high_count": 0,
                    }
                sev = row.get("severity", "")
                max_cvss = float(row.get("max_cvss", 0) or 0)
                host_totals[tgt]["max_cvss"] = max(host_totals[tgt]["max_cvss"], max_cvss)
                if sev == "critical":
                    host_totals[tgt]["critical_count"] += int(row.get("finding_count", 1))
                elif sev == "high":
                    host_totals[tgt]["high_count"] += int(row.get("finding_count", 1))
                host_totals[tgt]["findings"].append({
                    "severity": sev,
                    "service": row.get("service", ""),
                    "cves": row.get("cves", []),
                    "max_cvss": max_cvss,
                    "count": row.get("finding_count", 1),
                    "remediation": row.get("remediations", ["No remediation available"])[0]
                    if isinstance(row.get("remediations"), list)
                    else row.get("remediations", ""),
                })

            hosts = list(host_totals.values())
            hosts.sort(key=lambda h: h["max_cvss"], reverse=True)

            return json.dumps({
                "status": "findings",
                "total_hosts": len(hosts),
                "hosts": hosts,
                "risk_summary": (
                    f"{sum(h['critical_count'] for h in hosts)} critical, "
                    f"{sum(h['high_count'] for h in hosts)} high findings across "
                    f"{len(hosts)} host(s)"
                ),
            }, indent=2)

        except Exception as e:
            log.exception("get_vuln_posture failed")
            return json.dumps({"error": str(e)})


# ── Tool 3: create_misp_event ─────────────────────────────────────────────────

@tool
def create_misp_event(
    title: str,
    description: str,
    iocs: str,
    tlp: str = "amber",
) -> str:
    """
    Create a new MISP threat intelligence event for a confirmed incident.
    This closes the feedback loop: an incident you investigated becomes
    permanent threat intel the team can reuse.

    IMPORTANT: Only call this when an investigation confirms a REAL incident
    (not a false positive). This writes to the live MISP database.
    The event will be created with TLP:AMBER and tagged origin:hayyan-internal.

    Args:
        title: Short event title — e.g. "Password Spray from 192.168.56.50 against hayyan.local"
        description: Detailed description of the incident, findings, and evidence.
        iocs: JSON string listing IoCs — e.g. '[{"type":"ip-dst","value":"1.2.3.4"},
              {"type":"domain","value":"evil.com"},{"type":"md5","value":"abc123..."}]'
              Supported types: ip-dst, ip-src, domain, url, md5, sha256, email-src, filename
        tlp: Traffic Light Protocol level: "white", "green", "amber", "red".
             Default "amber" — share within your org only.
    """
    with audit_tool_call("create_misp_event", {"title": title, "tlp": tlp}):
        cfg = get_settings()
        if not cfg.misp_api_key:
            return json.dumps({
                "created": False,
                "error": "MISP_API_KEY not configured. Add it to .env and restart.",
            })

        # Parse IoCs
        try:
            ioc_list = json.loads(iocs) if isinstance(iocs, str) else iocs
        except json.JSONDecodeError as e:
            return json.dumps({
                "created": False,
                "error": f"Invalid IoC JSON: {e}. Format: [{{'type':'ip-dst','value':'1.2.3.4'}}]",
            })

        tlp_tag_map = {
            "white": "tlp:white",
            "green": "tlp:green",
            "amber": "tlp:amber",
            "red": "tlp:red",
        }
        tlp_tag = tlp_tag_map.get(tlp.lower(), "tlp:amber")

        event_payload = {
            "Event": {
                "info": title,
                "distribution": 0,     # 0 = Your organisation only
                "threat_level_id": 2,  # 2 = Medium
                "analysis": 1,         # 1 = Ongoing
                "Tag": [
                    {"name": tlp_tag},
                    {"name": "origin:hayyan-internal"},
                    {"name": "source:ai-soc-agent"},
                ],
                "Attribute": [],
            }
        }

        # Add description as free-text attribute
        event_payload["Event"]["Attribute"].append({
            "type": "comment",
            "value": description,
            "category": "Other",
            "to_ids": False,
            "distribution": 0,
        })

        # Map IoC types to MISP attribute categories
        ioc_category_map = {
            "ip-dst": "Network activity",
            "ip-src": "Network activity",
            "domain": "Network activity",
            "url": "Network activity",
            "md5": "Payload delivery",
            "sha256": "Payload delivery",
            "email-src": "Payload delivery",
            "filename": "Artifacts dropped",
        }

        for ioc in ioc_list:
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if not ioc_type or not ioc_value:
                continue
            event_payload["Event"]["Attribute"].append({
                "type": ioc_type,
                "value": ioc_value,
                "category": ioc_category_map.get(ioc_type, "Other"),
                "to_ids": ioc_type in ("ip-dst", "ip-src", "domain", "md5", "sha256"),
                "distribution": 0,
                "comment": ioc.get("comment", ""),
            })

        try:
            resp = requests.post(
                f"{_misp_base()}/events",
                headers=_misp_headers(),
                json=event_payload,
                verify=_misp_verify(),
                timeout=15,
            )
            resp.raise_for_status()
            result = resp.json()
            event_id = result.get("Event", {}).get("id", "unknown")
            event_uuid = result.get("Event", {}).get("uuid", "")

            return json.dumps({
                "created": True,
                "event_id": event_id,
                "event_uuid": event_uuid,
                "title": title,
                "ioc_count": len(ioc_list),
                "tlp": tlp_tag,
                "url": f"{_misp_base()}/events/view/{event_id}",
                "message": (
                    f"MISP event #{event_id} created with {len(ioc_list)} IoC(s). "
                    f"View at {_misp_base()}/events/view/{event_id}"
                ),
            }, indent=2)

        except requests.exceptions.ConnectionError:
            return json.dumps({
                "created": False,
                "error": f"Cannot connect to MISP at {_misp_base()}. Is it running?",
            })
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                return json.dumps({"created": False, "error": "MISP API key invalid or expired."})
            return json.dumps({"created": False, "error": f"MISP HTTP error: {e}"})
        except Exception as e:
            log.exception("create_misp_event failed")
            return json.dumps({"created": False, "error": str(e)})


ALL_MISP_TOOLS = [
    query_misp_ioc,
    get_vuln_posture,
    create_misp_event,
]
