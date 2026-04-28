# Final Corrected Docs - Canonical Runtime State

This document is the single source of truth for the stabilized Task 2 runtime.

## Canonical Values

- Splunk Web UI: http://localhost:8080
- Splunk REST API: https://localhost:8088
- Splunk HEC endpoint: http://localhost:8086/services/collector/event
- HayyanSOC dashboard: http://localhost:8080/en-US/app/HayyanSOC/threat_dashboard
- MISP UI/API base URL: https://127.0.0.1:8443
- AI Agent API: http://localhost:8500
- Rocky scanner node: 192.168.56.20

## Canonical IOC Correlation Model

- IOC sync is lookup-based, not detection-time index-scan based.
- Source of IOC truth in Splunk detections: `misp_ioc_lookup.csv` via `inputlookup`.
- Script path: `scripts/misp_sync_splunk.py`.
- Output file: `data/misp_ioc_lookup.csv`.
- If Splunk REST lookup upload is rejected, the script uses controlled chunked `outputlookup` jobs.
- Current validated IOC count: 4,995 unique IOCs.

## Canonical Scanner Model

- Rocky is the authorized scanner node.
- `python scripts/deploy_rocky.py` deploys the scanner pack, verifies Nuclei/Trivy, writes `splunkhec.env`, and enables the timer.
- `python scripts/test_scanners.py` runs a fast Trivy validation scan using the controlled demo fixture.
- Current validated scanner run: `run-20260428-171022`.
- Current validated findings: 46 Trivy findings in `vuln_scans` with 6 critical, 20 high, and 20 medium.

## Required .env Runtime Expectations

- `MISP_URL=https://127.0.0.1:8443`
- `MISP_API_KEY` is present and valid
- `MISP_ALLOW_WRITE=false` unless a live MISP write is explicitly approved
- `SPLUNK_HOST=localhost`
- `SPLUNK_PORT=8088`
- `SPLUNK_HEC_URL=http://localhost:8086`
- `SPLUNK_HEC_TOKEN` is present and valid
- `ROCKY_HOST=192.168.56.20`
- `ROCKY_SCAN_DIR=/opt/hayyan-scan`

## Validation Commands

```powershell
python scripts/validate_splunk.py
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
python scripts/deploy_rocky.py
python scripts/test_scanners.py
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500
```

## Useful Splunk Searches

```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type | sort -count
```

```spl
index=vuln_scans scanid="run-20260428-171022"
| stats count by scanner, severity, target
```

```spl
index=ai_soc_audit
| stats count by tool_name, status
```

## Important Clarifications

- The `misp_iocs` index can still exist for HEC/index validation, but production IOC correlation in this lab is lookup-based.
- Use `https://127.0.0.1:8443` for host-side MISP browser/API operations.
- Rocky uses VMnet2-reachable URLs written into `/opt/hayyan-scan/config/splunkhec.env`.
- AI chat testing with Groq/OpenRouter/Gemini sends prompt context to an external provider and requires explicit approval when using lab-derived data.
