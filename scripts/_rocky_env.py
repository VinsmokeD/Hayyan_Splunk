from __future__ import annotations

import os
import shlex
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parent.parent


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip().strip('"').strip("'")
    return {**env, **os.environ}


ENV = load_env()


def require(name: str) -> str:
    value = ENV.get(name, "").strip()
    if not value or value.startswith("your_"):
        raise RuntimeError(f"Required setting {name} is missing. Add it to .env or export it.")
    return value


def rocky_host() -> str:
    return ENV.get("ROCKY_HOST", ENV.get("ROCKY_IP", "")).strip()


def rocky_user() -> str:
    return require("ROCKY_USER")


def rocky_password() -> str:
    return require("ROCKY_PASSWORD")


def rocky_scan_dir() -> str:
    return ENV.get("ROCKY_SCAN_DIR", "/opt/hayyan-scan").rstrip("/")


def connect() -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        rocky_host(),
        username=rocky_user(),
        password=rocky_password(),
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return ssh


def sudo_command(command: str) -> str:
    password = rocky_password()
    return f"printf '%s\\n' {shlex.quote(password)} | sudo -S bash -lc {shlex.quote(command)}"
