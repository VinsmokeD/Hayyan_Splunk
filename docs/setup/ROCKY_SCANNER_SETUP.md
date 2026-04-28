# Rocky Linux Scanner Setup Guide - Hayyan SOC Lab

## Overview

Rocky Linux (`192.168.56.20`) is the authorized scanner node for the Hayyan SOC. It runs Nuclei and Trivy, normalizes scanner output, and pushes findings into Splunk HEC index `vuln_scans`.

Any scan from a source other than `192.168.56.20` should be treated as rogue or unscheduled activity unless explicitly approved.

## Host-Side Deployment

From the Windows project root:

```powershell
python scripts/deploy_rocky.py
```

The deploy script:

- Connects to Rocky over SSH using `ROCKY_HOST`, `ROCKY_USER`, and `ROCKY_PASSWORD`.
- Verifies or installs Nuclei and Trivy.
- Copies scanner scripts into `/opt/hayyan-scan`.
- Writes `/opt/hayyan-scan/config/splunkhec.env` with only the scanner-side values needed for HEC and MISP.
- Installs systemd units and enables `hayyan-scan.timer`.

Required `.env` values:

```bash
ROCKY_HOST=192.168.56.20
ROCKY_USER=mahmoud
ROCKY_PASSWORD=your_rocky_ssh_password_here
ROCKY_SCAN_DIR=/opt/hayyan-scan
SPLUNK_HEC_URL=http://localhost:8086
SPLUNK_HEC_TOKEN=your_hec_token_here
MISP_URL=https://127.0.0.1:8443
MISP_API_KEY=your_misp_api_key_here
MISP_ALLOW_WRITE=false
```

When deployed to Rocky, host-local URLs are translated to VMnet2-reachable URLs such as `http://192.168.56.1:8086` and `https://192.168.56.1:8443`.

## Fast Validation Scan

Run:

```powershell
python scripts/test_scanners.py
```

By default this uses:

```bash
ROCKY_TEST_SCAN_ARGS=--trivy
ROCKY_TEST_SCAN_PROFILE=demo
```

The demo profile scans `/opt/hayyan-scan/demo-fixtures/vulnerable-python`, a controlled vulnerable dependency manifest. Trivy produces real CVE findings without weakening the Rocky host or requiring a long Nuclei run.

Latest validated run:

- Scan ID: `run-20260428-171022`
- Findings: 46 Trivy findings
- Severity: 6 critical, 20 high, 20 medium
- HEC delivery: 46 sent, 0 failed
- MISP mirroring: skipped because `MISP_ALLOW_WRITE=false`

## Full Scheduled Scan

The systemd timer remains the operational path:

```bash
systemctl list-timers --all | grep hayyan-scan
sudo systemctl start hayyan-scan.service
```

Full scans run `/opt/hayyan-scan/orchestrator.sh`, which can execute both Nuclei and Trivy. Full Nuclei scans can be slow in a small lab, so use the fast validation path for demos.

## Splunk Verification

```spl
index=vuln_scans scanid="run-20260428-171022"
| stats count by scanner, severity, target
| sort -count
```

```spl
index=vuln_scans scanid="run-20260428-171022"
| head 5
| table scanid scanner cveid severity cvssscore target service remediation
```

Expected normalized fields:

- `scanid`
- `scanner`
- `cveid`
- `cvssscore`
- `severity`
- `target`
- `service`
- `remediation`
- `referenceurl`

## Rogue Scan Simulation

Run the rogue scan from a host that is not Rocky:

```bash
bash scripts/rocky/rogue_scan_sim.sh --target 192.168.56.20 --intensity medium
```

Then check Splunk for the rogue scanner detection. The SOC story is that scheduled scans from Rocky are authorized, while similar behavior from another source is suspicious.

## Troubleshooting

| Problem | Fix |
|---|---|
| `trivy: command not found` | Rerun `python scripts/deploy_rocky.py`; it verifies/installs Trivy from the official Aqua Security RPM repo. |
| `nuclei: command not found` | Rerun `python scripts/deploy_rocky.py`; it installs the pinned Nuclei binary if missing. |
| HEC token missing on Rocky | Rerun deployment and confirm `.env` contains `SPLUNK_HEC_TOKEN`. |
| HEC push fails | Confirm Rocky can reach `http://192.168.56.1:8086/services/collector/event`. |
| MISP write occurs unexpectedly | Keep `MISP_ALLOW_WRITE=false`; scanner-side MISP mirroring will skip live writes. |
| Full Nuclei scan is slow | Use `python scripts/test_scanners.py` for demo validation and reserve full scans for scheduled runs. |
