import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import connect, rocky_host, sudo_command

def run_remote(ssh, cmd):
    print(f"\n--- Running: {cmd} ---")
    stdin, stdout, stderr = ssh.exec_command(sudo_command(cmd))
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode('ascii', errors='replace')
    err = stderr.read().decode('ascii', errors='replace')
    print(f"Exit Status: {exit_status}")
    if out: print(f"STDOUT:\n{out}")
    if err: print(f"STDERR:\n{err}")

def fix_deps():
    print(f"Connecting to Rocky ({rocky_host()})...")
    ssh = connect()
    
    # 1. Install Trivy via Yum
    run_remote(ssh, "cat << EOF | sudo tee /etc/yum.repos.d/trivy.repo\n[trivy]\nname=Trivy repository\nbaseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\\$releasever/\\$basearch/\ngpgcheck=0\nenabled=1\nEOF")
    run_remote(ssh, "yum -y install trivy")
    run_remote(ssh, "chmod +x /usr/local/bin/nuclei")
    run_remote(ssh, "ln -sf /usr/local/bin/nuclei /usr/bin/nuclei")
    run_remote(ssh, "ln -sf /usr/local/bin/trivy /usr/bin/trivy")
    
    # 3. Verify installations
    run_remote(ssh, "/usr/local/bin/trivy --version")
    run_remote(ssh, "/usr/local/bin/nuclei -version")
    
    ssh.close()

if __name__ == "__main__":
    fix_deps()
