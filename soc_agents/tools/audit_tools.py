"""
Hayyan SOC Lab — Agent Audit Logging Tool
==========================================
Logs every AI SOC agent tool call to the Splunk ai_soc_audit index
via HEC. This gives you full observability into agent behaviour:
- Which tools were called during each investigation
- How long each tool took
- What the agent's inputs were
- Whether enrichment was skipped (missed opportunity detection)

The audit log is written inside each tool via a decorator, so it's
transparent to the agent and doesn't affect tool output.

Usage — wrap any tool call:
    from .audit_tools import audit_tool_call

    with audit_tool_call("query_misp_ioc", {"indicator": indicator}, thread_id):
        result = actual_tool_logic(indicator)
"""
import json
import logging
import os
import ssl
import time
import traceback
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
def _load_env() -> dict:
    env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    cfg: dict = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                cfg[k.strip()] = v.strip()
    return {**cfg, **os.environ}

_env = _load_env()

_HEC_URL   = _env.get("SPLUNK_HEC_URL", "http://localhost:8086")
_HEC_TOKEN = _env.get("SPLUNK_HEC_TOKEN", "")
_AUDIT_INDEX = "ai_soc_audit"
_AGENT_ID = "hayyan-soc-agent-v1"

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

_hec_available: bool | None = None  # None = not yet checked


def _check_hec_available() -> bool:
    """Check HEC token is configured. Cache result."""
    global _hec_available
    if _hec_available is None:
        _hec_available = bool(_HEC_TOKEN)
        if not _hec_available:
            log.debug("[AuditTools] SPLUNK_HEC_TOKEN not set — audit logging disabled")
    return _hec_available


def _send_audit_event(event: dict) -> None:
    """Fire-and-forget HEC send. Never raises — audit must not block agent."""
    if not _check_hec_available():
        return
    try:
        payload = json.dumps({
            "time": event.get("timestamp", time.time()),
            "index": _AUDIT_INDEX,
            "sourcetype": "hayyan:ai:audit",
            "source": "hayyan-soc-agent",
            "host": "soc-agent-host",
            "event": event,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{_HEC_URL}/services/collector/event",
            data=payload,
            headers={
                "Authorization": f"Splunk {_HEC_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=3) as _:
            pass  # Discard response — fire and forget
    except Exception:
        pass  # Never block the agent on audit failure


@contextmanager
def audit_tool_call(
    tool_name: str,
    inputs: dict[str, Any],
    thread_id: str = "unknown",
) -> Generator[dict, None, None]:
    """
    Context manager that records a tool call start/finish to ai_soc_audit.

    Usage:
        result_holder = {}
        with audit_tool_call("query_misp_ioc", {"indicator": ip}, thread_id) as ctx:
            ctx["result"] = do_the_work()
        return ctx["result"]
    """
    start_ts = time.time()
    ctx: dict = {}

    # Emit start event
    _send_audit_event({
        "event_type": "tool_call_start",
        "agent_id": _AGENT_ID,
        "thread_id": thread_id,
        "tool_name": tool_name,
        "inputs": _safe_truncate(inputs),
        "timestamp": start_ts,
    })

    try:
        yield ctx

        elapsed_ms = int((time.time() - start_ts) * 1000)
        # Emit success event
        _send_audit_event({
            "event_type": "tool_call_complete",
            "agent_id": _AGENT_ID,
            "thread_id": thread_id,
            "tool_name": tool_name,
            "inputs": _safe_truncate(inputs),
            "elapsed_ms": elapsed_ms,
            "result_preview": _safe_truncate(ctx.get("result", ""), max_len=300),
            "timestamp": time.time(),
            "status": "success",
        })

    except Exception as exc:
        elapsed_ms = int((time.time() - start_ts) * 1000)
        _send_audit_event({
            "event_type": "tool_call_error",
            "agent_id": _AGENT_ID,
            "thread_id": thread_id,
            "tool_name": tool_name,
            "inputs": _safe_truncate(inputs),
            "elapsed_ms": elapsed_ms,
            "error": str(exc)[:200],
            "traceback": traceback.format_exc()[:500],
            "timestamp": time.time(),
            "status": "error",
        })
        raise  # Always re-raise — don't swallow agent errors


def _safe_truncate(obj: Any, max_len: int = 200) -> Any:
    """Truncate strings for token-safe audit logging."""
    if isinstance(obj, str):
        return obj[:max_len] + ("…" if len(obj) > max_len else "")
    if isinstance(obj, dict):
        return {k: _safe_truncate(v, max_len // 2) for k, v in list(obj.items())[:10]}
    if isinstance(obj, (list, tuple)):
        return [_safe_truncate(v, max_len // 2) for v in obj[:5]]
    return obj


def log_investigation_start(alert_name: str, thread_id: str) -> None:
    """Log the start of a new investigation thread."""
    _send_audit_event({
        "event_type": "investigation_start",
        "agent_id": _AGENT_ID,
        "thread_id": thread_id,
        "alert_name": alert_name,
        "timestamp": time.time(),
    })


def log_investigation_complete(
    thread_id: str,
    verdict: str,
    confidence: float,
    tools_used: list[str],
    misp_checked: bool,
    vuln_checked: bool,
    misp_created: bool,
) -> None:
    """Log the final investigation result with enrichment quality metrics."""
    _send_audit_event({
        "event_type": "investigation_complete",
        "agent_id": _AGENT_ID,
        "thread_id": thread_id,
        "verdict": verdict,
        "confidence": confidence,
        "tools_used": tools_used,
        "tool_count": len(tools_used),
        "misp_ioc_checked": misp_checked,
        "vuln_posture_checked": vuln_checked,
        "misp_event_created": misp_created,
        "enrichment_complete": misp_checked and vuln_checked,
        "timestamp": time.time(),
    })
