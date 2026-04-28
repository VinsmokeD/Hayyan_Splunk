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

def install_deps():
    print(f"Connecting to Rocky ({rocky_host()})...")
    ssh = connect()
    
    # 1. Install pip and dependencies
    run_remote(ssh, "yum install -y python3-pip wget unzip curl")
    run_remote(ssh, "pip3 install requests")
    
    # 2. Install Trivy
    run_remote(ssh, "rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.rpm || echo 'Trivy already installed'")
    
    # 3. Install Nuclei
    run_remote(ssh, "wget -qO nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.2.7/nuclei_3.2.7_linux_amd64.zip && unzip -o nuclei.zip && mv nuclei /usr/local/bin/ && rm -f nuclei.zip")
    
    # 4. Verify installations
    run_remote(ssh, "trivy --version")
    run_remote(ssh, "nuclei -version")
    
    ssh.close()

if __name__ == "__main__":
    install_deps()
