# Final Corrected Docs (Canonical Runtime State)

This document is the single source of truth for the stabilized lab runtime.

## Canonical Values

- Splunk Web UI: http://localhost:8080
- Splunk REST API: https://localhost:8088
- Splunk HEC endpoint: http://localhost:8086/services/collector/event
- HayyanSOC dashboard: http://localhost:8080/en-US/app/HayyanSOC/threat_dashboard
- MISP UI/API base URL: https://127.0.0.1:8443
- MISP admin login: admin@admin.test / MispAdmin2026!

## Canonical IOC Correlation Model

- IOC sync is lookup-based, not index-based.
- Source of IOC truth in Splunk detections: misp_ioc_lookup.csv via inputlookup.
- Script path: scripts/misp_sync_splunk.py
- Output file: data/misp_ioc_lookup.csv
- In this lab, if Splunk REST lookup upload is rejected, Docker fallback copy is used by the sync script.

## Required .env Runtime Expectations

- MISP_URL=https://127.0.0.1:8443
- MISP_API_KEY is present and valid
- SPLUNK_HOST=localhost
- SPLUNK_PORT=8088
- SPLUNK_HEC_URL=http://localhost:8086

## Validation Commands

```powershell
python scripts/validate_splunk.py
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
python -c "import requests,urllib3; urllib3.disable_warnings(); d={'search':'| inputlookup misp_ioc_lookup.csv | head 5','output_mode':'json','exec_mode':'oneshot'}; r=requests.post('https://localhost:8088/services/search/jobs',auth=('admin','Hayyan@2024!'),verify=False,data=d,timeout=30); print(r.status_code); print(r.text[:800])"
```

## Important Clarifications

- The misp_iocs index can still exist for general ingestion tests, but production IOC correlation in this lab is lookup-based.
- Use only https://127.0.0.1:8443 for browser/API MISP operations on the host to avoid mixed-origin and CSRF/session issues.
- Do not use https://localhost/auth_keys/index (missing :8443).
