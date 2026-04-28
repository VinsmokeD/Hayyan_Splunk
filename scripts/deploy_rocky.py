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


def _remote_lab_url(value: str, default: str) -> str:
    """Translate host-local URLs into URLs Rocky can reach over VMnet2."""
    raw = (value or default).strip()
    return raw.replace("localhost", "192.168.56.1").replace("127.0.0.1", "192.168.56.1")


def build_scanner_env() -> str:
    """Build the minimal env file needed by scanner-side delivery scripts."""
    hec_url = _remote_lab_url(ENV.get("ROCKY_SPLUNK_HEC_URL", ENV.get("SPLUNK_HEC_URL", "")), "http://192.168.56.1:8086")
    misp_url = _remote_lab_url(ENV.get("ROCKY_MISP_URL", ENV.get("MISP_URL", "")), "https://192.168.56.1:8443")
    lines = {
        "SPLUNK_HEC_URL": hec_url,
        "SPLUNK_HEC_TOKEN": ENV.get("SPLUNK_HEC_TOKEN", ""),
        "MISP_URL": misp_url,
        "MISP_API_KEY": ENV.get("MISP_API_KEY", ""),
        "MISP_VERIFY_SSL": ENV.get("MISP_VERIFY_SSL", "false"),
        "MISP_ALLOW_WRITE": ENV.get("MISP_ALLOW_WRITE", "false"),
        "ROCKY_IP": ENV.get("ROCKY_IP", ROCKY_HOST),
    }
    return "\n".join(f"{key}={value}" for key, value in lines.items()) + "\n"


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


def ensure_scanner_dependencies(ssh: paramiko.SSHClient) -> None:
    """Install Nuclei and Trivy when they are missing on Rocky."""
    print("Verifying scanner dependencies...")
    install_cmd = r"""
set -e
if ! command -v trivy >/dev/null 2>&1; then
  cat > /etc/yum.repos.d/trivy.repo <<'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
  dnf install -y trivy
fi
if ! command -v nuclei >/dev/null 2>&1; then
  dnf install -y wget unzip
  cd /tmp
  rm -f nuclei.zip nuclei
  wget -qO nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.2.7/nuclei_3.2.7_linux_amd64.zip
  unzip -o nuclei.zip >/dev/null
  install -m 0755 nuclei /usr/local/bin/nuclei
  rm -f nuclei.zip nuclei
fi
trivy --version
nuclei -version
"""
    run(ssh, install_cmd, sudo=True)


def deploy_to_rocky() -> int:
    require_config()
    print(f"Connecting to Rocky scanner node {ROCKY_HOST} as {ROCKY_USER}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh = connect()
        print("[OK] SSH connection established")
        ensure_scanner_dependencies(ssh)

        scan_dir_q = shlex.quote(ROCKY_SCAN_DIR)
        tmp_q = shlex.quote(REMOTE_TMP)

        print("Creating scanner directory structure...")
        run(
            ssh,
            (
                f"mkdir -p {scan_dir_q}/config {scan_dir_q}/scanners "
                f"{scan_dir_q}/pipeline {scan_dir_q}/logs {scan_dir_q}/systemd "
                f"{scan_dir_q}/demo-fixtures && "
                f"chown -R {shlex.quote(ROCKY_USER)}:{shlex.quote(ROCKY_USER)} {scan_dir_q}"
            ),
            sudo=True,
        )

        print("Transferring scanner and systemd files...")
        run(ssh, f"rm -rf {tmp_q} && mkdir -p {tmp_q}")
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(str(ROOT / "scripts" / "rocky"), recursive=True, remote_path=REMOTE_TMP)
            scp.put(str(ROOT / "systemd"), recursive=True, remote_path=REMOTE_TMP)

        with ssh.open_sftp() as sftp:
            with sftp.file(posixpath.join(REMOTE_TMP, "splunkhec.env"), "w") as remote_env:
                remote_env.write(build_scanner_env())

        remote_rocky = posixpath.join(REMOTE_TMP, "rocky")
        remote_systemd = posixpath.join(REMOTE_TMP, "systemd")

        print("Installing files into /opt/hayyan-scan and systemd...")
        install_cmd = (
            f"cp {shlex.quote(remote_rocky)}/*.sh {scan_dir_q}/scanners/ && "
            f"cp {shlex.quote(remote_rocky)}/*.py {scan_dir_q}/pipeline/ && "
            f"cp {shlex.quote(remote_rocky)}/*.yaml {scan_dir_q}/config/ && "
            f"cp {tmp_q}/splunkhec.env {scan_dir_q}/config/splunkhec.env && "
            f"if [ -d {shlex.quote(remote_rocky)}/demo-fixtures ]; then cp -R {shlex.quote(remote_rocky)}/demo-fixtures/* {scan_dir_q}/demo-fixtures/; fi && "
            f"chmod 600 {scan_dir_q}/config/splunkhec.env && "
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
