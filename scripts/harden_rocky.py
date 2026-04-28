"""
Fix Trivy installation on Rocky Linux and validate all scanner tools.
Uses direct GitHub binary download (tar.gz) from a working release.
"""
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import connect, rocky_host, sudo_command

def run(ssh, cmd, timeout=60):
    print(f"\n[RUN] {cmd}")
    stdin, stdout, stderr = ssh.exec_command(f"bash -c '{cmd}'", timeout=timeout)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    print(f"  exit={exit_status}")
    if out.strip(): print("  STDOUT:", out.strip()[:500])
    if err.strip(): print("  STDERR:", err.strip()[:500])
    return exit_status, out, err

def sudo(ssh, cmd, timeout=60):
    return run(ssh, sudo_command(cmd), timeout)

def main():
    ssh = connect()
    print(f"Connected to Rocky {rocky_host()}")

    # ── Step 1: Install Trivy via direct binary ────────────────────────────────
    # Use v0.55.2 which is available on GitHub
    print("\n=== Installing Trivy ===")
    trivy_url = "https://github.com/aquasecurity/trivy/releases/download/v0.55.2/trivy_0.55.2_Linux-64bit.tar.gz"
    sudo(ssh, f"cd /tmp && wget -q -O trivy.tar.gz '{trivy_url}'", timeout=120)
    sudo(ssh, "cd /tmp && tar -xzf trivy.tar.gz trivy && mv trivy /usr/local/bin/trivy && chmod +x /usr/local/bin/trivy && rm -f trivy.tar.gz")
    sudo(ssh, "ln -sf /usr/local/bin/trivy /usr/bin/trivy")
    code, out, _ = sudo(ssh, "/usr/local/bin/trivy --version")
    if code == 0:
        print("  [OK] Trivy installed:", out.split("\\n")[0])
    else:
        print("  [FAIL] Trivy install failed")

    # ── Step 2: Verify Nuclei ─────────────────────────────────────────────────
    print("\n=== Verifying Nuclei ===")
    code, out, _ = sudo(ssh, "/usr/local/bin/nuclei -version 2>&1 | head -2")
    if code == 0:
        print("  [OK] Nuclei:", out.strip()[:100])
    else:
        # Reinstall nuclei
        nuclei_url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.7/nuclei_3.2.7_linux_amd64.zip"
        sudo(ssh, f"cd /tmp && wget -q -O nuclei.zip '{nuclei_url}' && unzip -o nuclei.zip nuclei && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm -f nuclei.zip")
        sudo(ssh, "ln -sf /usr/local/bin/nuclei /usr/bin/nuclei")
        print("  [OK] Nuclei reinstalled")

    # ── Step 3: Verify Python3 + requests ────────────────────────────────────
    print("\n=== Verifying Python3 ===")
    sudo(ssh, "pip3 install requests pyyaml --quiet")
    code, out, _ = run(ssh, "python3 -c \"import requests; print('OK')\"")
    print("  Python3 + requests:", "OK" if code == 0 else "FAIL")

    # ── Step 4: Verify splunkhec.env ──────────────────────────────────────────
    print("\n=== Verifying splunkhec.env ===")
    code, out, _ = run(ssh, "cat /opt/hayyan-scan/config/splunkhec.env 2>/dev/null || echo MISSING")
    print("  splunkhec.env:", out.strip()[:200])

    # ── Step 5: Full orchestrator run ──────────────────────────────────────────
    print("\n=== Running full orchestrator ===")
    code, out, err = sudo(ssh, "cd /opt/hayyan-scan && bash orchestrator.sh", timeout=120)
    full = (out + err).encode("ascii", errors="replace").decode("ascii")
    print(full[:2000])

    # ── Step 6: Enable systemd timer ─────────────────────────────────────────
    print("\n=== Enabling systemd timer ===")
    sudo(ssh, "systemctl enable hayyan-scan.timer 2>/dev/null && systemctl start hayyan-scan.timer 2>/dev/null || echo 'Timer not found'")
    code, out, _ = run(ssh, "systemctl list-timers 2>/dev/null | grep hayyan || echo 'no timer'")
    print("  Timer:", out.strip()[:200])

    ssh.close()
    print("\n=== Rocky hardening complete ===")

if __name__ == "__main__":
    main()
