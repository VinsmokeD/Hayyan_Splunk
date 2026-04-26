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
    with audit_tool_call("run_splunk_query", {"spl": spl, "earliest": earliest, "latest": latest}):
        ok, reason = validate_spl(spl)
        if not ok:
            return f"QUERY BLOCKED by guardrails: {reason}. Revise the query and try again."
        try:
            results = _get_client().run_search(spl, earliest=earliest, latest=latest, max_results=max_results)
            if not results:
                return "Query returned 0 results."
            return json.dumps(results, indent=2)
        except Exception as e:
            return f"Splunk query error: {str(e)}"


@tool
def get_triggered_alerts() -> str:
    """
    Retrieve all currently triggered (fired) Splunk alerts.
    Returns alert name, trigger time, severity, and count of triggers.
    Use this to understand what the SIEM has flagged as suspicious activity.
    """
    with audit_tool_call("get_triggered_alerts", {}):
        try:
            alerts = _get_client().get_triggered_alerts()
            if not alerts:
                return "No triggered alerts at this time."
            return json.dumps(alerts, indent=2)
        except Exception as e:
            return f"Error fetching alerts: {str(e)}"


@tool
def get_index_stats() -> str:
    """
    Get statistics for all Splunk indexes: event counts, data size, and time range.
    Use this to understand what data is available and how recent it is.
    Available indexes: linux_audit, linux_web, linux_secure, windows_events, sysmon
    """
    try:
        stats = _get_client().get_index_stats()
        return json.dumps(stats, indent=2)
    except Exception as e:
        return f"Error fetching index stats: {str(e)}"


@tool
def get_saved_searches() -> str:
    """
    List all saved searches and scheduled alerts configured in Splunk.
    Shows the SPL query, cron schedule, and alert type for each.
    Use this to understand what detections are actively monitoring the environment.
    """
    try:
        searches = _get_client().get_saved_searches()
        return json.dumps(searches, indent=2)
    except Exception as e:
        return f"Error fetching saved searches: {str(e)}"


@tool
def investigate_ip(ip_address: str, time_range: str = "-24h") -> str:
    """
    Investigate all Splunk activity for a specific IP address across all indexes.
    Runs multiple targeted queries to build a complete picture of the IP's behavior.

    Args:
        ip_address: The IP to investigate (e.g., 192.168.56.10)
        time_range: How far back to look (default -24h)
    """
    client = _get_client()
    findings = {}

    queries = {
        "windows_logon_failures": f'index=windows_events EventCode=4625 (src_ip="{ip_address}" OR IpAddress="{ip_address}") | stats count by Account_Name, EventCode | sort -count',
        "windows_successful_logons": f'index=windows_events EventCode=4624 (src_ip="{ip_address}" OR IpAddress="{ip_address}") | stats count by Account_Name | sort -count',
        "web_requests": f'index=linux_web clientip="{ip_address}" | stats count by status, request | sort -count | head 20',
        "ssh_attempts": f'index=linux_secure src="{ip_address}" | stats count by action | sort -count',
        "sysmon_network": f'index=sysmon EventCode=3 DestinationIp="{ip_address}" OR SourceIp="{ip_address}" | stats count by Image, DestinationIp, DestinationPort | sort -count | head 20',
    }

    for label, spl in queries.items():
        try:
            results = client.run_search(spl, earliest=time_range, max_results=20)
            findings[label] = results if results else "No results"
        except Exception as e:
            findings[label] = f"Error: {str(e)}"

    return json.dumps(findings, indent=2)


@tool
def investigate_user(username: str, time_range: str = "-24h") -> str:
    """
    Investigate all Splunk activity for a specific Active Directory user.
    Covers logon events, process creation, privilege escalation, and AD changes.

    Args:
        username: The AD username to investigate (e.g., jdoe, akhalil, svc_it)
        time_range: How far back to look (default -24h)
    """
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
            results = client.run_search(spl, earliest=time_range, max_results=20)
            findings[label] = results if results else "No results"
        except Exception as e:
            findings[label] = f"Error: {str(e)}"

    return json.dumps(findings, indent=2)


@tool
def check_splunk_health() -> str:
    """
    Check Splunk connectivity and return basic health information.
    Use this first to verify Splunk is reachable before running queries.
    """
    client = _get_client()
    reachable = client.ping()
    if not reachable:
        return "ERROR: Splunk is not reachable. Check that port 8089 is exposed on the Docker container."

    try:
        stats = client.get_index_stats()
        total_events = sum(int(idx.get("total_event_count") or 0) for idx in stats)
        return json.dumps({
            "status": "healthy",
            "reachable": True,
            "total_events_across_indexes": total_events,
            "indexes": [i["name"] for i in stats if int(i.get("total_event_count") or 0) > 0],
        }, indent=2)
    except Exception as e:
        return f"Splunk reachable but error fetching stats: {str(e)}"


ALL_SPLUNK_TOOLS = [
    check_splunk_health,
    validate_spl_query,
    run_splunk_query,
    get_triggered_alerts,
    get_index_stats,
    get_saved_searches,
    investigate_ip,
    investigate_user,
]
