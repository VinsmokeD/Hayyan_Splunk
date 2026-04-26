# Rocky Linux Scanner — Deployment Guide

Run these commands on Rocky Linux (192.168.56.20) as root.

## 1. Install dependencies

```bash
# Nuclei (Go binary)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or: download prebuilt binary
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip
unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && chmod +x /usr/local/bin/nuclei

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Python requests + urllib3 (for push scripts)
pip3 install requests urllib3
```

## 2. Deploy the scanner

```bash
# Copy scanner directory to Rocky Linux
scp -r scripts/rocky-scanner/ root@192.168.56.20:/opt/hayyan-scan/

# On Rocky:
chmod +x /opt/hayyan-scan/orchestrator.sh
chmod +x /opt/hayyan-scan/scanners/*.sh
mkdir -p /opt/hayyan-scan/logs /opt/hayyan-scan/raw
```

## 3. Configure credentials

```bash
cp /opt/hayyan-scan/config/splunk_hec.env.example /opt/hayyan-scan/config/splunk_hec.env
chmod 600 /opt/hayyan-scan/config/splunk_hec.env
# Edit and fill in SPLUNK_HEC_TOKEN and MISP_API_KEY
nano /opt/hayyan-scan/config/splunk_hec.env
```

## 4. Install systemd units

```bash
cp /opt/hayyan-scan/systemd/hayyan-scan.service /etc/systemd/system/
cp /opt/hayyan-scan/systemd/hayyan-scan.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable hayyan-scan.timer
systemctl start hayyan-scan.timer
# Verify:
systemctl status hayyan-scan.timer
```

## 5. Test manually

```bash
# Run the full scan right now (takes ~5-20 min)
sudo /opt/hayyan-scan/orchestrator.sh

# Check logs
journalctl -u hayyan-scan -f
# or:
tail -f /opt/hayyan-scan/logs/scan-*.log
```

## 6. Verify Splunk is receiving data

In Splunk search: `index=vuln_scans | head 10`

## Authorized vs. Rogue Scanner Demo

To demonstrate the difference between authorized and rogue scanning:

- **Authorized**: runs from 192.168.56.20 at 02:30 daily (this scanner)
- **Rogue**: run Nuclei from a *different* IP — the "Web Scanner Detected" alert fires

This demonstrates detection-engineering: same traffic pattern, distinguished by source context.
