"""
SPL guardrails — validate every generated query before execution.

Called automatically inside run_splunk_query AND exposed as an agent tool
so the AI can pre-check its own queries.
"""
import re
from langchain_core.tools import tool

# Commands that modify or destroy data
_BLOCKED_COMMANDS = [
    "| delete",
    "| drop",
    "| collect",
    "| outputlookup",
    "| sendemail",
    "| sendalert",
    "| script",
    "| run",
    "restart",
    "| map",     # can execute arbitrary searches in loops
]

# Splunk admin REST endpoints that should never appear in SPL
_BLOCKED_PATTERNS = [
    r"\|\s*rest\s+.*?/services/(authentication|authorization|deployment|server/control)",
]

_MAX_TIME_DAYS = 30


def validate_spl(query: str) -> tuple[bool, str]:
    """
    Validate an SPL query before execution.

    Returns:
        (True, "OK") if safe to run
        (False, reason) if blocked
    """
    if not query or not query.strip():
        return False, "Empty query"

    q_lower = query.lower()

    for cmd in _BLOCKED_COMMANDS:
        if cmd.lower() in q_lower:
            return False, f"Blocked command: '{cmd}'"

    for pattern in _BLOCKED_PATTERNS:
        if re.search(pattern, q_lower):
            return False, f"Blocked REST path pattern detected"

    # Warn (but don't block) on unbounded time range via earliest
    # The time range is enforced at the client level anyway, but flag it
    if "earliest=-all" in q_lower or "earliest=0" in q_lower:
        return False, "Unbounded time range (earliest=-all or earliest=0) is not allowed"

    return True, "OK"


@tool
def validate_spl_query(spl: str) -> str:
    """
    Validate an SPL query for safety before running it.

    Call this before run_splunk_query when you're generating a new query.
    Returns "VALID" or a description of why the query is blocked.

    Args:
        spl: The SPL query string to validate
    """
    ok, reason = validate_spl(spl)
    if ok:
        return "VALID — query is safe to execute"
    return f"BLOCKED — {reason}"
