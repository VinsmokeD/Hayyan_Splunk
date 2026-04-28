import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))

from _rocky_env import connect

ssh = connect()
stdin, stdout, stderr = ssh.exec_command("bash -lc 'ls -la /tmp/'")
print(stdout.read().decode())
ssh.close()
