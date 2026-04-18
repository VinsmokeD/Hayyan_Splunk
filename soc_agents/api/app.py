"""
Hayyan SOC Agent API

Endpoints:
  GET  /              -> Web UI
  GET  /api/health    -> Splunk + API health check
  GET  /api/alerts    -> Live triggered Splunk alerts
  GET  /api/indexes   -> Splunk index stats
  POST /api/chat      -> Single-turn chat (returns full report)
  WS   /ws/chat       -> Streaming chat with live tool + token updates
"""
import json
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from ..agents.soc_graph import soc_graph
from ..core.config import get_settings
from ..core.splunk_client import SplunkClient, SplunkConnectionError

log = logging.getLogger(__name__)
_cfg = get_settings()

app = FastAPI(title="Hayyan SOC Agents", version="2.0.0")
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
    scheme = _splunk._scheme or "unknown"
    host = f"{_splunk._host}:{_splunk._port}"
    return JSONResponse({
        "status": "ok",
        "splunk": f"connected via {scheme}://{host}" if splunk_ok else f"unreachable at {host}",
        "model": _cfg.model_name,
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
        final_text = final.content if final and hasattr(final, "content") else ""
        return JSONResponse({
            "thread_id": thread_id,
            "report": final_text,
        })
    except Exception as e:
        log.exception("chat invoke failed")
        return JSONResponse({"error": str(e)}, status_code=500)


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
                await websocket.send_json({"type": "error", "content": "empty message"})
                continue

            config = {"configurable": {"thread_id": thread_id}}
            state = {"messages": [HumanMessage(content=message)]}

            await websocket.send_json({
                "type": "status",
                "content": "Thinking...",
                "thread_id": thread_id,
            })

            try:
                async for event in soc_graph.astream(state, config=config, stream_mode="updates"):
                    for node_name, node_output in event.items():
                        msgs = node_output.get("messages", []) if isinstance(node_output, dict) else []
                        for msg in msgs:
                            # Tool call announcement
                            if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
                                for tc in msg.tool_calls:
                                    await websocket.send_json({
                                        "type": "tool_call",
                                        "tool": tc.get("name", "unknown"),
                                        "args": tc.get("args", {}),
                                    })
                            # Tool result
                            elif isinstance(msg, ToolMessage):
                                preview = (msg.content[:200] + "...") if len(msg.content) > 200 else msg.content
                                await websocket.send_json({
                                    "type": "tool_result",
                                    "tool": getattr(msg, "name", "unknown"),
                                    "content": preview,
                                })
                            # Final AI message (no tool calls)
                            elif isinstance(msg, AIMessage) and msg.content:
                                await websocket.send_json({
                                    "type": "report",
                                    "content": msg.content,
                                    "thread_id": thread_id,
                                })

                await websocket.send_json({"type": "done", "thread_id": thread_id})

            except Exception as e:
                log.exception("ws_chat graph error")
                await websocket.send_json({"type": "error", "content": str(e)})

    except WebSocketDisconnect:
        pass
