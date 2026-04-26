from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache

# Always resolve .env relative to this file so uvicorn worker processes
# (which may have a different CWD on Windows) can still find it.
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    # ── LLM Providers (fallback chain: OpenRouter → Groq → Ollama → Gemini) ────
    # OpenRouter — https://openrouter.ai  ($10 top-up → 1000 free req/day)
    openrouter_api_key: str = ""
    openrouter_model: str = "deepseek/deepseek-chat-v3-0324:free"

    # Groq — https://console.groq.com  (14,400 free req/day)
    groq_api_key: str = ""
    model_name: str = "llama-3.3-70b-versatile"
    backup_model_name: str = "llama-3.1-8b-instant"  # kept for compat

    # Ollama — local, always available (set base URL if non-default)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:4b"

    # Google Gemini — https://aistudio.google.com
    google_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

    # ── Splunk REST API ────────────────────────────────────────────────────────
    splunk_host: str = "localhost"
    splunk_port: int = 8088  # Docker: host:8088 → container:8089 (REST API)
    splunk_username: str = "admin"
    splunk_password: str = "Hayyan@2024!"
    splunk_scheme: str = "https"
    splunk_verify_ssl: bool = False

    # ── Splunk HEC (HTTP Event Collector) ─────────────────────────────────────
    # Create token: Splunk UI → Settings → Data Inputs → HTTP Event Collector
    splunk_hec_token: str = ""
    splunk_hec_url: str = "https://localhost:8088"

    # ── MISP Threat Intelligence Platform ─────────────────────────────────────
    # Deploy: docker compose -f docker-compose.misp.yml up -d
    # Get API key: MISP UI → Administration → Auth Keys → Add Authentication Key
    misp_url: str = "https://localhost:8443"
    misp_api_key: str = ""
    misp_verify_ssl: bool = False
    # Min CVSS score to create MISP events from scanner findings
    misp_vuln_min_cvss: float = 7.0

    # ── API Server ─────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8500

    # ── Observability ──────────────────────────────────────────────────────────
    langsmith_api_key: str = ""
    langsmith_tracing: bool = False
    langsmith_project: str = "hayyan-ai-soc"
    chroma_persist_dir: str = "./data/chroma_db"
    checkpoint_db: str = "./data/checkpoints.sqlite"

    class Config:
        env_file = str(_ENV_FILE)
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
