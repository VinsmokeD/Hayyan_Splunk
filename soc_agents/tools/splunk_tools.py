import json
from langchain_core.tools import tool
from ..core.splunk_client import SplunkClient
from .spl_guardrails import validate_spl, validate_spl_query

_client: SplunkClient | None = None

from .audit_tools import audit_tool_call


def _get_client() -> SplunkClient:
    global _client
    if _client is None:
        _client = SplunkClient()
    return _client


def _run_checked_search(client: SplunkClient, spl: str, earliest: str, max_results: int) -> list[dict]:
    ok, reason = validate_spl(spl)
    if not ok:
        raise ValueError(f"SPL blocked by guardrails: {reason}")
    return client.run_search(spl, earliest=earliest, max_results=max_results)


@tool
def run_splunk_query(spl: str, earliest: str = "-24h", latest: str = "now", max_results: int = 50) -> str:
    """
    Execute a Splunk SPL query and return results as JSON.

    Args:
        spl: The SPL (Search Processing Language) query to run.
             Examples:
               index=windows_events EventCode=4625 | stats count by src_ip
               index=linux_secure "Failed password" | head 20
               index=sysmon EventCode=1 | table _time, host, CommandLine
        earliest: Earliest time for search (default -24h). Examples: -1h, -7d, -30d
        latest: Latest time for search (default now)
        max_results: Maximum number of results to return (default 50)
    """
    with audit_tool_call("run_splunk_query", {"spl": spl, "earliest": earliest, "latest": latest}) as audit:
        ok, reason = validate_spl(spl)
        if not ok:
            result = f"QUERY BLOCKED by guardrails: {reason}. Revise the query and try again."
            audit["result"] = result
            return result
        try:
            results = _get_client().run_search(spl, earliest=earliest, latest=latest, max_results=max_results)
            if not results:
                result = "Query returned 0 results."
            else:
                result = json.dumps(results, indent=2)
            audit["result"] = result
            return result
        except Exception as e:
            result = f"Splunk query error: {str(e)}"
            audit["result"] = result
            return result


@tool
def get_triggered_alerts() -> str:
    """
    Retrieve all currently triggered (fired) Splunk alerts.
    Returns alert name, trigger time, severity, and count of triggers.
    Use this to understand what the SIEM has flagged as suspicious activity.
    """
    with audit_tool_call("get_triggered_alerts", {}) as audit:
        try:
            alerts = _get_client().get_triggered_alerts()
            if not alerts:
                result = "No triggered alerts at this time."
            else:
                result = json.dumps(alerts, indent=2)
            audit["result"] = result
            return result
        except Exception as e:
            result = f"Error fetching alerts: {str(e)}"
            audit["result"] = result
            return result


@tool
def get_index_stats() -> str:
    """
    Get statistics for all Splunk indexes: event counts, data size, and time range.
    Use this to understand what data is available and how recent it is.
    Available indexes: linux_audit, linux_web, linux_secure, windows_events, sysmon
    """
    with audit_tool_call("get_index_stats", {}) as audit:
        try:
            stats = _get_client().get_index_stats()
            result = json.dumps(stats, indent=2)
            audit["result"] = result
            return result
        except Exception as e:
            result = f"Error fetching index stats: {str(e)}"
            audit["result"] = result
            return result


@tool
def get_saved_searches() -> str:
    """
    List all saved searches and scheduled alerts configured in Splunk.
    Shows the SPL query, cron schedule, and alert type for each.
    Use this to understand what detections are actively monitoring the environment.
    """
    with audit_tool_call("get_saved_searches", {}) as audit:
        try:
            searches = _get_client().get_saved_searches()
            result = json.dumps(searches, indent=2)
            audit["result"] = result
            return result
        except Exception as e:
            result = f"Error fetching saved searches: {str(e)}"
            audit["result"] = result
            return result


@tool
def investigate_ip(ip_address: str, time_range: str = "-24h") -> str:
    """
    Investigate all Splunk activity for a specific IP address across all indexes.
    Runs multiple targeted queries to build a complete picture of the IP's behavior.

    Args:
        ip_address: The IP to investigate (e.g., 192.168.56.10)
        time_range: How far back to look (default -24h)
    """
    with audit_tool_call("investigate_ip", {"ip_address": ip_address, "time_range": time_range}) as audit:
        client = _get_client()
        findings = {}

        queries = {
            "windows_logon_failures": f'index=windows_events EventCode=4625 (src_ip="{ip_address}" OR IpAddress="{ip_address}") | stats count by Account_Name, EventCode | sort -count',
            "windows_successful_logons": f'index=windows_events EventCode=4624 (src_ip="{ip_address}" OR IpAddress="{ip_address}") | stats count by Account_Name | sort -count',
            "web_requests": f'index=linux_web clientip="{ip_address}" | stats count by status, request | sort -count | head 20',
            "ssh_attempts": f'index=linux_secure src="{ip_address}" | stats count by action | sort -count',
            "sysmon_network": f'index=sysmon (EventCode=3 DestinationIp="{ip_address}") OR (EventCode=3 SourceIp="{ip_address}") | stats count by Image, DestinationIp, DestinationPort | sort -count | head 20',
        }

        for label, spl in queries.items():
            try:
                results = _run_checked_search(client, spl, earliest=time_range, max_results=20)
                findings[label] = results if results else "No results"
            except Exception as e:
                findings[label] = f"Error: {str(e)}"

        result = json.dumps(findings, indent=2)
        audit["result"] = result
        return result


@tool
def investigate_user(username: str, time_range: str = "-24h") -> str:
    """
    Investigate all Splunk activity for a specific Active Directory user.
    Covers logon events, process creation, privilege escalation, and AD changes.

    Args:
        username: The AD username to investigate (e.g., jdoe, akhalil, svc_it)
        time_range: How far back to look (default -24h)
    """
    with audit_tool_call("investigate_user", {"username": username, "time_range": time_range}) as audit:
        client = _get_client()
        findings = {}

        queries = {
            "logon_events": f'index=windows_events EventCode IN (4624, 4625, 4634, 4648) (Account_Name="{username}" OR TargetUserName="{username}") | stats count by EventCode, IpAddress | sort -count',
            "privilege_use": f'index=windows_events EventCode IN (4672, 4673, 4674) TargetUserName="{username}" | stats count by EventCode, PrivilegeList | sort -count',
            "ad_changes_by_user": f'index=windows_events EventCode IN (4720, 4722, 4723, 4724, 4725, 4726, 4728) SubjectUserName="{username}" | table _time, EventCode, TargetUserName',
            "process_creation": f'index=sysmon EventCode=1 User="*\\\\{username}" | stats count by Image, CommandLine | sort -count | head 20',
            "kerberos": f'index=windows_events EventCode IN (4768, 4769, 4770) (AccountName="{username}" OR ServiceName="{username}") | stats count by EventCode, ServiceName | sort -count',
        }

        for label, spl in queries.items():
            try:
                results = _run_checked_search(client, spl, earliest=time_range, max_results=20)
                findings[label] = results if results else "No results"
            except Exception as e:
                findings[label] = f"Error: {str(e)}"

        result = json.dumps(findings, indent=2)
        audit["result"] = result
        return result


@tool
def hunt_recent_misp_iocs(history_window: str = "-7d", ioc_sync_window: str = "-24h") -> str:
    """
    Retrospectively hunt newly imported MISP IoCs across historical lab logs.

    Use this when asking whether new threat intel was already seen in earlier
    activity. It searches web, DNS, Sysmon hash, and Windows network evidence
    using the `misp_ioc_lookup.csv` lookup refreshed by MISP sync.

    Args:
        history_window: How far back to hunt in telemetry. Default: -7d.
        ioc_sync_window: How recently the IoC was imported/synced. Default: -24h.
    """
    with audit_tool_call(
        "hunt_recent_misp_iocs",
        {"history_window": history_window, "ioc_sync_window": ioc_sync_window},
    ) as audit:
        client = _get_client()
        findings = {}
        queries = {
            "ip_hits_web": (
                f'index=linux_web earliest={history_window} '
                f'[| inputlookup misp_ioc_lookup.csv '
                f' | where (ioc_type="ip-dst" OR ioc_type="ip-src") '
                f' | where sync_epoch > relative_time(now(), "{ioc_sync_window}") '
                f' | rename ioc_value as clientip | fields clientip] '
                f'| stats count, min(_time) as first_seen, max(_time) as last_seen, '
                f'values(request) as requests by clientip | sort -count'
            ),
            "domain_hits_sysmon_dns": (
                f'index=sysmon EventCode=22 earliest={history_window} '
                f'[| inputlookup misp_ioc_lookup.csv '
                f' | where (ioc_type="domain" OR ioc_type="hostname") '
                f' | where sync_epoch > relative_time(now(), "{ioc_sync_window}") '
                f' | rename ioc_value as QueryName | fields QueryName] '
                f'| stats count, min(_time) as first_seen, max(_time) as last_seen, '
                f'values(Image) as processes by QueryName, host | sort -count'
            ),
            "hash_hits_sysmon": (
                f'index=sysmon EventCode=1 earliest={history_window} '
                f'[| inputlookup misp_ioc_lookup.csv '
                f' | where (ioc_type="md5" OR ioc_type="sha256") '
                f' | where sync_epoch > relative_time(now(), "{ioc_sync_window}") '
                f' | rename ioc_value as Hashes | fields Hashes] '
                f'| table _time, host, Image, CommandLine, Hashes'
            ),
            "ip_hits_windows": (
                f'index=windows_events earliest={history_window} '
                f'[| inputlookup misp_ioc_lookup.csv '
                f' | where (ioc_type="ip-dst" OR ioc_type="ip-src") '
                f' | where sync_epoch > relative_time(now(), "{ioc_sync_window}") '
                f' | rename ioc_value as IpAddress | fields IpAddress] '
                f'| stats count, min(_time) as first_seen, max(_time) as last_seen '
                f'by IpAddress, EventCode | sort -count'
            ),
        }

        for label, spl in queries.items():
            try:
                results = _run_checked_search(client, spl, earliest=history_window, max_results=50)
                findings[label] = results if results else "No results"
            except Exception as e:
                findings[label] = f"Error: {str(e)}"

        hit_count = sum(1 for value in findings.values() if value != "No results" and not str(value).startswith("Error:"))
        result = json.dumps({
            "hunt_type": "new_misp_iocs_vs_historical_logs",
            "history_window": history_window,
            "ioc_sync_window": ioc_sync_window,
            "hit_categories": hit_count,
            "findings": findings,
        }, indent=2)
        audit["result"] = result
        return result


@tool
def check_splunk_health() -> str:
    """
    Check Splunk connectivity and return basic health information.
    Use this first to verify Splunk is reachable before running queries.
    """
    with audit_tool_call("check_splunk_health", {}) as audit:
        client = _get_client()
        reachable = client.ping()
        if not reachable:
            result = "ERROR: Splunk is not reachable. Check that host port 8088 is mapped to container port 8089 and credentials are correct."
            audit["result"] = result
            return result

        try:
            stats = client.get_index_stats()
            total_events = sum(int(idx.get("total_event_count") or 0) for idx in stats)
            result = json.dumps({
                "status": "healthy",
                "reachable": True,
                "total_events_across_indexes": total_events,
                "indexes": [i["name"] for i in stats if int(i.get("total_event_count") or 0) > 0],
            }, indent=2)
            audit["result"] = result
            return result
        except Exception as e:
            result = f"Splunk reachable but error fetching stats: {str(e)}"
            audit["result"] = result
            return result


ALL_SPLUNK_TOOLS = [
    check_splunk_health,
    validate_spl_query,
    run_splunk_query,
    get_triggered_alerts,
    get_index_stats,
    get_saved_searches,
    investigate_ip,
    investigate_user,
    hunt_recent_misp_iocs,
]
