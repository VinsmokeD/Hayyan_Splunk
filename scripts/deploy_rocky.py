#!/usr/bin/env python3
"""
Deploy the Hayyan scanner pack to Rocky Linux.

Configuration is loaded from .env and environment variables. Required:
ROCKY_HOST, ROCKY_USER, ROCKY_PASSWORD. ROCKY_SCAN_DIR defaults to
/opt/hayyan-scan if omitted.
"""
from __future__ import annotations

import os
import posixpath
import shlex
import sys
from pathlib import Path

import paramiko
from scp import SCPClient

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
REMOTE_TMP = ENV.get("ROCKY_TMP_DIR", "/tmp/hayyan-rocky-deploy").rstrip("/")


def require_config() -> None:
    if not ROCKY_PASSWORD:
        print("[ERROR] ROCKY_PASSWORD is required for SSH/sudo deployment.")
        print(f"        Add ROCKY_PASSWORD=... to {ROOT / '.env'} or export it in the shell.")
        sys.exit(2)
    if not (ROOT / "scripts" / "rocky").is_dir():
        print("[ERROR] scripts/rocky directory not found.")
        sys.exit(2)
    if not (ROOT / "systemd").is_dir():
        print("[ERROR] systemd directory not found.")
        sys.exit(2)


def run(ssh: paramiko.SSHClient, command: str, sudo: bool = False) -> None:
    if sudo:
        remote = f"printf '%s\\n' {shlex.quote(ROCKY_PASSWORD)} | sudo -S bash -lc {shlex.quote(command)}"
    else:
        remote = f"bash -lc {shlex.quote(command)}"
    stdin, stdout, stderr = ssh.exec_command(remote)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    status = stdout.channel.recv_exit_status()
    if out:
        print(out.encode("ascii", errors="replace").decode("ascii"))
    if err:
        safe_err = err.replace(ROCKY_PASSWORD, "***")
        print(safe_err.encode("ascii", errors="replace").decode("ascii"))
    if status != 0:
        raise RuntimeError(f"Remote command failed ({status}): {command}")


def deploy_to_rocky() -> int:
    require_config()
    print(f"Connecting to Rocky scanner node {ROCKY_HOST} as {ROCKY_USER}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh = connect()
        print("[OK] SSH connection established")

        scan_dir_q = shlex.quote(ROCKY_SCAN_DIR)
        tmp_q = shlex.quote(REMOTE_TMP)

        print("Creating scanner directory structure...")
        run(
            ssh,
            (
                f"mkdir -p {scan_dir_q}/config {scan_dir_q}/scanners "
                f"{scan_dir_q}/pipeline {scan_dir_q}/logs {scan_dir_q}/systemd && "
                f"chown -R {shlex.quote(ROCKY_USER)}:{shlex.quote(ROCKY_USER)} {scan_dir_q}"
            ),
            sudo=True,
        )

        print("Transferring scanner and systemd files...")
        run(ssh, f"rm -rf {tmp_q} && mkdir -p {tmp_q}")
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(str(ROOT / "scripts" / "rocky"), recursive=True, remote_path=REMOTE_TMP)
            scp.put(str(ROOT / "systemd"), recursive=True, remote_path=REMOTE_TMP)

        remote_rocky = posixpath.join(REMOTE_TMP, "rocky")
        remote_systemd = posixpath.join(REMOTE_TMP, "systemd")

        print("Installing files into /opt/hayyan-scan and systemd...")
        install_cmd = (
            f"cp {shlex.quote(remote_rocky)}/*.sh {scan_dir_q}/scanners/ && "
            f"cp {shlex.quote(remote_rocky)}/*.py {scan_dir_q}/pipeline/ && "
            f"cp {shlex.quote(remote_rocky)}/*.yaml {scan_dir_q}/config/ && "
            f"mv {scan_dir_q}/scanners/orchestrator.sh {scan_dir_q}/orchestrator.sh && "
            f"mv {scan_dir_q}/scanners/rogue_scan_sim.sh {scan_dir_q}/rogue_scan_sim.sh && "
            f"chmod +x {scan_dir_q}/scanners/*.sh {scan_dir_q}/*.sh && "
            f"cp {shlex.quote(remote_systemd)}/* /etc/systemd/system/ && "
            "systemctl daemon-reload && "
            "systemctl enable hayyan-scan.timer"
        )
        run(ssh, install_cmd, sudo=True)

        print("[OK] Rocky scanner pack deployed")
        print("Next validation command: python scripts/test_scanners.py")
        return 0
    except Exception as exc:
        print(f"[ERROR] Deployment failed: {exc}")
        return 1
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(deploy_to_rocky())
