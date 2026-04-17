"""
Hayyan SOC Agents — entry point.

Usage:
    python main.py
    # OR
    uvicorn main:app --reload --host 0.0.0.0 --port 8500
"""
from soc_agents.core.config import get_settings
from soc_agents.api.app import app  # noqa: F401 — re-exported for uvicorn

if __name__ == "__main__":
    import uvicorn

    cfg = get_settings()
    print(f"\n🔷  Hayyan SOC Agents  —  http://{cfg.api_host}:{cfg.api_port}")
    print(f"🔗  Splunk target      —  {cfg.splunk_scheme}://{cfg.splunk_host}:{cfg.splunk_port}")
    print(f"🤖  LLM model         —  {cfg.model_name}\n")

    uvicorn.run(
        "soc_agents.api.app:app",
        host=cfg.api_host,
        port=cfg.api_port,
        reload=True,
        log_level="info",
    )
