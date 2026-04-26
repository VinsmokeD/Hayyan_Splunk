"""
Hayyan SOC Agent API

Endpoints:
  GET  /                  -> Web UI
  GET  /api/health        -> Splunk + API health check
  GET  /api/alerts        -> Live triggered Splunk alerts
  GET  /api/indexes       -> Splunk index stats
  GET  /api/misp/health   -> MISP connectivity check
  GET  /api/vuln-posture  -> Vulnerability posture summary from vuln_scans index
  POST /api/chat          -> Single-turn chat (blocking, returns full report)
  WS   /ws/chat           -> Streaming chat with live tool + result updates
"""
import json
import logging
import uuid
from pathlib import Path

import requests
import urllib3

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from ..agents.soc_graph import soc_graph, soc_graph_backup
from ..core.config import get_settings
from ..core.splunk_client import SplunkClient, SplunkConnectionError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)
_cfg = get_settings()


def _extract_text(content) -> str:
    """Normalize various content formats to a plain string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
            if not isinstance(block, dict) or block.get("type") == "text"
        )
    return str(content)


app = FastAPI(title="Hayyan SOC Agents", version="2.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_splunk = SplunkClient()
_UI_PATH = Path(__file__).parent.parent / "ui"


# ── Static UI ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_path = _UI_PATH / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Hayyan SOC Agents</h1><p>UI not found.</p>")


# ── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    splunk_ok = _splunk.ping()
    scheme = _splunk._scheme or _cfg.splunk_scheme
    host = f"{_splunk._host}:{_splunk._port}"
    model_display = _cfg.model_name.replace("llama-3.3-70b-versatile", "Llama 3.3 70B")
    return JSONResponse({
        "status": "ok",
        "splunk_connected": splunk_ok,
        "splunk": f"connected via {scheme}://{host}" if splunk_ok else f"unreachable at {host}",
        "splunk_host": host,
        "model": _cfg.model_name,
        "model_display": model_display,
        "provider": "Groq",
    })


@app.get("/api/alerts")
async def get_alerts():
    try:
        alerts = _splunk.get_triggered_alerts()
        return JSONResponse({"alerts": alerts})
    except SplunkConnectionError as e:
        return JSONResponse({"error": f"Splunk unreachable: {e}", "alerts": []}, status_code=503)
    except Exception as e:
        log.exception("get_alerts failed")
        return JSONResponse({"error": str(e), "alerts": []}, status_code=500)


@app.get("/api/indexes")
async def get_indexes():
    try:
        stats = _splunk.get_index_stats()
        return JSONResponse({"indexes": stats})
    except SplunkConnectionError as e:
        return JSONResponse({"error": f"Splunk unreachable: {e}", "indexes": []}, status_code=503)
    except Exception as e:
        log.exception("get_indexes failed")
        return JSONResponse({"error": str(e), "indexes": []}, status_code=500)


@app.get("/api/misp/health")
async def misp_health():
    """Check MISP connectivity and return basic status."""
    cfg = get_settings()
    if not cfg.misp_api_key:
        return JSONResponse({
            "connected": False,
            "status": "not_configured",
            "message": "MISP_API_KEY not set in .env",
            "deploy_cmd": "docker compose -f docker-compose.misp.yml up -d",
        })
    try:
        resp = requests.get(
            f"{cfg.misp_url.rstrip('/')}/servers/getPyMISPVersion",
            headers={"Authorization": cfg.misp_api_key, "Accept": "application/json"},
            verify=cfg.misp_verify_ssl,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        return JSONResponse({
            "connected": True,
            "status": "ok",
            "misp_url": cfg.misp_url,
            "version": data.get("version", "unknown"),
        })
    except requests.exceptions.ConnectionError:
        return JSONResponse({
            "connected": False,
            "status": "unreachable",
            "message": f"Cannot connect to MISP at {cfg.misp_url}",
        }, status_code=503)
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else 0
        return JSONResponse({
            "connected": False,
            "status": "auth_error" if code == 403 else "http_error",
            "message": str(e),
        }, status_code=503)
    except Exception as e:
        return JSONResponse({"connected": False, "status": "error", "message": str(e)}, status_code=503)


@app.get("/api/vuln-posture")
async def vuln_posture(target: str = "", severity: str = "high"):
    """
    Return vulnerability posture summary from the vuln_scans Splunk index.
    Query params:
      target   — filter to a specific host IP or name (empty = all hosts)
      severity — minimum severity: low | medium | high | critical  (default: high)
    """
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    sev_threshold = sev_order.get(severity.lower(), 2)
    sev_filter = " OR ".join(
        f'severity="{s}"' for s, v in sev_order.items() if v >= sev_threshold
    )
    target_filter = f'target="{target}"' if target else ""
    where_parts = " ".join(filter(None, [target_filter, f"({sev_filter})"]))

    spl = (
        f'index=vuln_scans {where_parts} '
        f'| stats count as findings, values(cve_id) as cves, max(cvss_score) as max_cvss '
        f'  by target, severity '
        f'| sort -max_cvss'
    )

    try:
        results = _splunk.run_search(spl, earliest="-30d", max_results=200)
        # Pivot into per-host summary for the dashboard
        hosts: dict[str, dict] = {}
        for row in results:
            tgt = row.get("target", "unknown")
            if tgt not in hosts:
                hosts[tgt] = {"target": tgt, "max_cvss": 0.0, "severities": {}}
            sev = row.get("severity", "unknown")
            hosts[tgt]["severities"][sev] = int(row.get("findings", 0))
            hosts[tgt]["max_cvss"] = max(hosts[tgt]["max_cvss"], float(row.get("max_cvss") or 0))

        sorted_hosts = sorted(hosts.values(), key=lambda h: h["max_cvss"], reverse=True)
        return JSONResponse({
            "hosts": sorted_hosts,
            "total_hosts": len(sorted_hosts),
            "last_scan_index": "vuln_scans",
        })
    except SplunkConnectionError as e:
        return JSONResponse({"error": f"Splunk unreachable: {e}", "hosts": []}, status_code=503)
    except Exception as e:
        log.exception("vuln_posture failed")
        return JSONResponse({"error": str(e), "hosts": []}, status_code=500)


@app.post("/api/chat")
async def chat(body: dict):
    message = body.get("message", "")
    thread_id = body.get("thread_id") or str(uuid.uuid4())
    if not message:
        return JSONResponse({"error": "message is required"}, status_code=400)

    config = {"configurable": {"thread_id": thread_id}}
    state = {"messages": [HumanMessage(content=message)]}

    try:
        result = soc_graph.invoke(state, config=config)
        messages = result.get("messages", [])
        final = messages[-1] if messages else None
        final_text = _extract_text(final.content) if final and hasattr(final, "content") else ""
        return JSONResponse({"thread_id": thread_id, "report": final_text})
    except Exception as e:
        msg = str(e)
        if "429" in msg or "rate_limit" in msg.lower():
            return JSONResponse(
                {"error": "Rate limit reached. Wait a moment and try again."},
                status_code=429,
            )
        log.exception("chat invoke failed")
        return JSONResponse({"error": msg}, status_code=500)


# ── WebSocket Streaming ───────────────────────────────────────────────────────

@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket):
    await websocket.accept()
    thread_id = str(uuid.uuid4())

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            message = data.get("message", "")
            thread_id = data.get("thread_id") or thread_id

            if not message:
                await websocket.send_json({"type": "error", "content": "Empty message"})
                continue

            config = {"configurable": {"thread_id": thread_id}}
            state = {"messages": [HumanMessage(content=message)]}

            await websocket.send_json({
                "type": "status",
                "content": "Analyzing request...",
                "thread_id": thread_id,
            })

            async def _stream_graph(graph, ws_state, ws_config):
                """Stream a graph and forward events over the websocket."""
                async for event in graph.astream(ws_state, config=ws_config, stream_mode="updates"):
                    for _node, node_output in event.items():
                        msgs = node_output.get("messages", []) if isinstance(node_output, dict) else []
                        for msg in msgs:
                            if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
                                for tc in msg.tool_calls:
                                    await websocket.send_json({
                                        "type": "tool_call",
                                        "tool": tc.get("name", "unknown"),
                                        "args": tc.get("args", {}),
                                    })
                            elif isinstance(msg, ToolMessage):
                                raw_content = _extract_text(msg.content)
                                preview = (raw_content[:300] + "...") if len(raw_content) > 300 else raw_content
                                await websocket.send_json({
                                    "type": "tool_result",
                                    "tool": getattr(msg, "name", "unknown"),
                                    "content": preview,
                                })
                            elif isinstance(msg, AIMessage) and msg.content:
                                text = _extract_text(msg.content)
                                if text.strip():
                                    await websocket.send_json({
                                        "type": "report",
                                        "content": text,
                                        "thread_id": thread_id,
                                    })

            try:
                await _stream_graph(soc_graph, state, config)
                await websocket.send_json({"type": "done", "thread_id": thread_id})

            except Exception as e:
                err_msg = str(e)
                is_rate_limit = "429" in err_msg or "rate_limit" in err_msg.lower()

                if is_rate_limit:
                    # Retry with backup model (llama-3.1-8b-instant — higher TPM)
                    log.warning("Primary model rate limited, retrying with backup model")
                    await websocket.send_json({
                        "type": "status",
                        "content": "Rate limit hit — switching to backup model...",
                    })
                    try:
                        # Fresh state for the backup (new thread so memory doesn't conflict)
                        backup_config = {"configurable": {"thread_id": thread_id + "-backup"}}
                        await _stream_graph(soc_graph_backup, state, backup_config)
                        await websocket.send_json({"type": "done", "thread_id": thread_id})
                    except Exception as e2:
                        log.exception("ws_chat backup graph error")
                        await websocket.send_json({
                            "type": "error",
                            "content": "Rate limit on both models. Wait ~60 seconds and try again.",
                        })
                else:
                    log.exception("ws_chat graph error")
                    await websocket.send_json({"type": "error", "content": err_msg})

    except WebSocketDisconnect:
        pass
