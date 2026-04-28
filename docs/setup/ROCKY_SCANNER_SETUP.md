# Rocky Linux Scanner Setup Guide — Hayyan SOC Lab

## Overview
Rocky Linux (`192.168.56.20`) is the **authorized scanner node** for the Hayyan SOC.
It runs Nuclei (web/network) and Trivy (filesystem/container) on a systemd timer,
normalizes findings, and pushes them to Splunk via HEC.

**Any scan from a source other than `192.168.56.20` should be treated as a rogue scan.**

---

## Step 1: SSH to Rocky Linux

```bash
ssh your_user@192.168.56.20
sudo -i
```

---

## Step 2: Install Nuclei

```bash
# Install Go (required for Nuclei)
dnf install -y golang

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
cp ~/go/bin/nuclei /usr/local/bin/

# Update templates
nuclei -update-templates

# Verify
nuclei -version
```

---

## Step 3: Install Trivy

```bash
# Add Trivy repository
cat > /etc/yum.repos.d/trivy.repo << 'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF

dnf install -y trivy

# Verify
trivy --version
```

---

## Step 4: Deploy the Scanner Pack

```bash
# Create directory structure
mkdir -p /opt/hayyan-scan/{config,scanners,pipeline,logs,systemd}

# Copy all files from this repo's scripts/rocky/ to Rocky
# From Windows host (using scp or copy-paste):
```

```powershell
# From Windows — copy scanner scripts to Rocky
scp scripts/rocky/* your_user@192.168.56.20:/tmp/hayyan-scan-scripts/
ssh your_user@192.168.56.20 "sudo cp -r /tmp/hayyan-scan-scripts/* /opt/hayyan-scan/"
```

```bash
# On Rocky — set permissions
chmod +x /opt/hayyan-scan/orchestrator.sh
chmod +x /opt/hayyan-scan/scanners/nuclei-web.sh
chmod +x /opt/hayyan-scan/scanners/trivy-fs.sh
chmod 600 /opt/hayyan-scan/config/splunkhec.env
```

---

## Step 5: Configure Splunk HEC Token

On the Windows host:
1. Splunk UI → Settings → Data Inputs → HTTP Event Collector → New Token
2. Name: `hayyan-scanner`
3. Index: `vuln_scans` (select only this index)
4. Copy the token

On Rocky Linux:
```bash
cat > /opt/hayyan-scan/config/splunkhec.env << 'EOF'
# Splunk HEC Configuration — DO NOT COMMIT THIS FILE
SPLUNK_HEC_URL=http://192.168.56.1:8086
SPLUNK_HEC_TOKEN=YOUR_TOKEN_HERE
MISP_URL=https://192.168.56.1:8443
MISP_API_KEY=YOUR_MISP_KEY_HERE
ROCKY_IP=192.168.56.20
EOF

chmod 600 /opt/hayyan-scan/config/splunkhec.env
```

---

## Step 6: Configure Targets

Edit `/opt/hayyan-scan/config/targets.yaml` and verify the target IPs match your lab topology.

Key targets:
- `http://192.168.56.10` — DC01 (Windows Server)
- `http://192.168.56.20` — Rocky Linux self-scan
- `https://192.168.56.1:8443` — MISP (self-scan for operational maturity)

---

## Step 7: Install systemd Units

```bash
# Copy systemd unit files
cp /opt/hayyan-scan/systemd/hayyan-scan.service /etc/systemd/system/
cp /opt/hayyan-scan/systemd/hayyan-scan.timer   /etc/systemd/system/

# Important: move scripts to expected paths
mkdir -p /opt/hayyan-scan/scanners /opt/hayyan-scan/pipeline
cp /opt/hayyan-scan/nuclei-web.sh /opt/hayyan-scan/scanners/
cp /opt/hayyan-scan/trivy-fs.sh   /opt/hayyan-scan/scanners/
cp /opt/hayyan-scan/normalize.py  /opt/hayyan-scan/pipeline/
cp /opt/hayyan-scan/push_splunk.py /opt/hayyan-scan/pipeline/
cp /opt/hayyan-scan/push_misp.py  /opt/hayyan-scan/pipeline/
cp /opt/hayyan-scan/orchestrator.sh /opt/hayyan-scan/

# Enable and start the timer
systemctl daemon-reload
systemctl enable hayyan-scan.timer
systemctl start hayyan-scan.timer

# Verify
systemctl status hayyan-scan.timer
systemctl list-timers | grep hayyan
```

---

## Step 8: Run First Manual Scan

```bash
# Test run (does NOT wait for timer)
sudo /opt/hayyan-scan/orchestrator.sh

# Watch the log in real-time
tail -f /opt/hayyan-scan/logs/scan-*.log
```

Expected output:
```
>>> [Nuclei] Starting web/network scan...
>>> [Trivy] Starting filesystem/container scan...
>>> [Pipeline] Normalizing findings to unified schema...
>>> [Pipeline] 47 findings normalized.
>>> [Pipeline] Pushing to Splunk HEC (index=vuln_scans)...
```

---

## Step 9: Verify in Splunk

```spl
index=vuln_scans | stats count by scanner, severity | sort -count
```

```spl
index=vuln_scans | head 5 | table scanid, scanner, cveid, severity, cvssscore, target, service
```

---

## Step 10: Test Rogue Scan Simulation

```bash
# Run from a DIFFERENT host (not Rocky Linux) to simulate unauthorized scanning
bash scripts/rocky/rogue_scan_sim.sh --target 192.168.56.20 --intensity medium

# Then check Splunk for the alert:
# "RISK-ADJUSTED - Scanner Detected from Non-Authorized Host"
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Nuclei not found | Ensure `/usr/local/bin/nuclei` exists and is executable |
| Trivy fails on /proc | Expected — Trivy skips /proc,/sys,/dev automatically |
| HEC push fails (401) | Check SPLUNK_HEC_TOKEN in splunkhec.env |
| HEC push fails (403) | HEC token not allowed for vuln_scans index — check Splunk settings |
| No findings in vuln_scans | Check scan log: `/opt/hayyan-scan/logs/scan-*.log` |
| Timer not firing | `systemctl list-timers | grep hayyan` — check NextElapses column |
