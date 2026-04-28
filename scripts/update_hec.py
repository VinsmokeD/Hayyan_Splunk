import os
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import ENV, connect, rocky_scan_dir, sudo_command

hec_url = ENV.get("SPLUNK_HEC_URL", "").strip()
hec_token = ENV.get("SPLUNK_HEC_TOKEN", "").strip()
if not hec_url or not hec_token:
    raise RuntimeError("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set in .env for update_hec.py")

ssh = connect()
scan_dir = rocky_scan_dir()
cmd = (
    f"echo SPLUNK_HEC_URL={hec_url} > {scan_dir}/config/splunkhec.env ; "
    f"echo SPLUNK_HEC_TOKEN={hec_token} >> {scan_dir}/config/splunkhec.env ; "
    f"chmod 600 {scan_dir}/config/splunkhec.env"
)
stdin, stdout, stderr = ssh.exec_command(sudo_command(cmd))

print("OUT:", stdout.read().decode())
print("ERR:", stderr.read().decode())
ssh.close()
