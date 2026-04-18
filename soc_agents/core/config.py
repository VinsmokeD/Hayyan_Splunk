from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache

# Always resolve .env relative to this file so uvicorn worker processes
# (which may have a different CWD on Windows) can still find it.
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    # LLM provider — set GROQ_API_KEY to use Groq (free, fast)
    # or GOOGLE_API_KEY to use Gemini
    groq_api_key: str = ""
    google_api_key: str = ""
    # Model name: Groq models → llama-3.3-70b-versatile, gemma2-9b-it
    #             Gemini models → gemini-2.0-flash, gemini-2.5-flash
    model_name: str = "llama-3.3-70b-versatile"

    splunk_host: str = "localhost"
    splunk_port: int = 8088
    splunk_username: str = "admin"
    splunk_password: str = "Hayyan@2024!"
    splunk_scheme: str = "https"
    splunk_verify_ssl: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8500
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
