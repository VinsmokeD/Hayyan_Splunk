#!/usr/bin/env python3
"""
Run one manual scanner validation on Rocky Linux.

This executes the deployed orchestrator, lists generated logs, and confirms the
systemd timer is registered. Configuration is read from .env/environment.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import paramiko

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import connect, load_env, rocky_host, rocky_password, rocky_scan_dir, rocky_user


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
ROCKY_HOST = rocky_host()
ROCKY_USER = rocky_user()
ROCKY_PASSWORD = rocky_password()
ROCKY_SCAN_DIR = rocky_scan_dir()
ROCKY_TEST_SCAN_ARGS = ENV.get("ROCKY_TEST_SCAN_ARGS", "--trivy")
ROCKY_TEST_SCAN_PROFILE = ENV.get("ROCKY_TEST_SCAN_PROFILE", "demo")


def require_config() -> None:
    if not ROCKY_PASSWORD:
        print("[ERROR] ROCKY_PASSWORD is required for scanner validation.")
        print(f"        Add ROCKY_PASSWORD=... to {ROOT / '.env'} or export it in the shell.")
        sys.exit(2)


def run_remote(ssh: paramiko.SSHClient, command: str, sudo: bool = True) -> int:
    print(f"\n--- Running: {command} ---")
    if sudo:
        remote = f"printf '%s\\n' {shlex.quote(ROCKY_PASSWORD)} | sudo -S bash -lc {shlex.quote(command)}"
    else:
        remote = f"bash -lc {shlex.quote(command)}"

    stdin, stdout, stderr = ssh.exec_command(remote)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    status = stdout.channel.recv_exit_status()

    if out:
        print("STDOUT:")
        print(out.encode("ascii", errors="replace").decode("ascii"))
    if err:
        print("STDERR:")
        print(err.replace(ROCKY_PASSWORD, "***").encode("ascii", errors="replace").decode("ascii"))
    if status != 0:
        print(f"[WARN] Command exited with status {status}")
    return status


def test_scanners() -> int:
    require_config()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"Connecting to Rocky scanner node {ROCKY_HOST} as {ROCKY_USER}...")
    try:
        ssh = connect()
        print("[OK] SSH connection established")

        scan_dir_q = shlex.quote(ROCKY_SCAN_DIR)
        failures = 0
        scan_args = " ".join(shlex.quote(part) for part in shlex.split(ROCKY_TEST_SCAN_ARGS))
        scan_profile_q = shlex.quote(ROCKY_TEST_SCAN_PROFILE)
        failures += int(run_remote(ssh, f"cd {scan_dir_q} && HAYYAN_SCAN_PROFILE={scan_profile_q} bash orchestrator.sh {scan_args}") != 0)
        failures += int(run_remote(ssh, f"find {scan_dir_q}/logs -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\\n' | sort | tail -20") != 0)
        failures += int(run_remote(ssh, "systemctl list-timers --all | grep hayyan-scan", sudo=False) != 0)

        if failures:
            print(f"\n[WARN] Scanner validation completed with {failures} warning(s).")
            return 1
        print("\n[OK] Scanner validation completed.")
        return 0
    except Exception as exc:
        print(f"[ERROR] Scanner validation failed: {exc}")
        return 1
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(test_scanners())
