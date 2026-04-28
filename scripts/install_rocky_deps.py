#!/usr/bin/env python3
"""Install scanner dependencies on the Rocky scanner node."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import connect, rocky_host, sudo_command


def run_remote(ssh, command: str) -> int:
    print(f"\n--- Running: {command.splitlines()[0][:80]} ---")
    stdin, stdout, stderr = ssh.exec_command(sudo_command(command))
    status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("ascii", errors="replace")
    err = stderr.read().decode("ascii", errors="replace")
    print(f"Exit Status: {status}")
    if out:
        print(f"STDOUT:\n{out}")
    if err:
        print(f"STDERR:\n{err}")
    return status


def install_deps() -> int:
    print(f"Connecting to Rocky ({rocky_host()})...")
    ssh = connect()
    try:
        commands = [
            "dnf install -y python3-pip wget unzip curl",
            "pip3 install requests",
            """cat > /etc/yum.repos.d/trivy.repo <<'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
dnf install -y trivy""",
            """cd /tmp
rm -f nuclei.zip nuclei
wget -qO nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.2.7/nuclei_3.2.7_linux_amd64.zip
unzip -o nuclei.zip
install -m 0755 nuclei /usr/local/bin/nuclei
rm -f nuclei.zip nuclei""",
            "trivy --version",
            "nuclei -version",
        ]
        failures = sum(1 for command in commands if run_remote(ssh, command) != 0)
        return 1 if failures else 0
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(install_deps())
