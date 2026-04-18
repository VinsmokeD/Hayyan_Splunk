"""
Hayyan SOC Agent API
- POST /api/chat          -> single-turn (returns full report)
- WebSocket /ws/chat      -> streaming token-by-token
- GET  /api/health        -> Splunk + API health check
- GET  /api/alerts        -> live triggered alerts
- GET  /api/indexes       -> Splunk index stats
"""
import json
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from langchain_core.messages import HumanMessage

from ..agents.soc_graph import soc_graph
from ..core.splunk_client import SplunkClient, SplunkConnectionError

log = logging.getLogger(__name__)

app = FastAPI(title="Hayyan SOC Agents", version="1.0.0")
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
        "model": "gemini-2.0-flash",
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
    thread_id = body.get("thread_id", str(uuid.uuid4()))
    if not message:
        return JSONResponse({"error": "message is required"}, status_code=400)

    config = {"configurable": {"thread_id": thread_id}}
    state = {"messages": [HumanMessage(content=message)]}

    try:
        result = soc_graph.invoke(state, config=config)
        return JSONResponse({
            "thread_id": thread_id,
            "report": result.get("report", ""),
            "messages": [
                {"role": "assistant", "content": m.content}
                for m in result.get("messages", [])
                if hasattr(m, "content") and m.content
            ][-1:],
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
            thread_id = data.get("thread_id", thread_id)

            if not message:
                await websocket.send_json({"type": "error", "content": "empty message"})
                continue

            config = {"configurable": {"thread_id": thread_id}}
            state = {"messages": [HumanMessage(content=message)]}

            await websocket.send_json({
                "type": "status",
                "content": "Analyzing request...",
                "thread_id": thread_id,
            })

            try:
                async for event in soc_graph.astream(state, config=config, stream_mode="updates"):
                    for node_name, node_output in event.items():
                        if node_name == "triage":
                            next_a = node_output.get("next_agent", "")
                            await websocket.send_json({
                                "type": "status",
                                "content": f"Routing to {next_a.replace('_', ' ')}...",
                            })

                        elif node_name in (
                            "query_agent", "alert_agent",
                            "investigation_agent", "report_agent",
                        ):
                            await websocket.send_json({
                                "type": "status",
                                "content": f"{node_name.replace('_', ' ').title()} working...",
                            })
                            for msg in node_output.get("messages", []):
                                if (
                                    hasattr(msg, "content")
                                    and msg.content
                                    and not getattr(msg, "tool_calls", None)
                                ):
                                    await websocket.send_json({
                                        "type": "partial",
                                        "content": msg.content,
                                        "agent": node_name,
                                    })

                        elif node_name == "synthesize":
                            report = node_output.get("report", "")
                            if report:
                                await websocket.send_json({
                                    "type": "report",
                                    "content": report,
                                    "thread_id": thread_id,
                                })

                await websocket.send_json({"type": "done", "thread_id": thread_id})

            except Exception as e:
                log.exception("ws_chat graph error")
                await websocket.send_json({"type": "error", "content": str(e)})

    except WebSocketDisconnect:
        pass
