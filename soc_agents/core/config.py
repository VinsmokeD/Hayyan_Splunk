from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache

# Always resolve .env relative to this file so uvicorn worker processes
# (which may have a different CWD on Windows) can still find it.
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    google_api_key: str = ""
    splunk_host: str = "localhost"
    splunk_port: int = 8088
    splunk_username: str = "admin"
    splunk_password: str = "Hayyan@2024!"
    splunk_scheme: str = "https"
    splunk_verify_ssl: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8500
    model_name: str = "gemini-2.5-flash"
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
