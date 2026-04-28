# 3-Minute Demo Script

## Goal

Show a stable, end-to-end SOC loop: platform health, IOC pipeline, and lookup-driven correlation.

## Minute 0:00-0:45 — Platform Health

Say:
"This lab is running a validated canonical stack: Splunk on 8080/8088/8086, MISP on 127.0.0.1:8443, and the HayyanSOC dashboard."

Run:
```powershell
docker compose -f docker-compose.splunk.yml ps
docker compose -f docker-compose.misp.yml ps
python scripts/validate_splunk.py
```

Show:
- Splunk UI: http://localhost:8080
- Dashboard: http://localhost:8080/en-US/app/HayyanSOC/threat_dashboard
- MISP UI: https://127.0.0.1:8443

## Minute 0:45-1:45 — IOC Sync Pipeline

Say:
"IOC correlation here is lookup-based. We sync published, to_ids=true MISP attributes into a Splunk lookup CSV."

Run:
```powershell
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
```

Then verify:
```powershell
python -c "import requests,urllib3; urllib3.disable_warnings(); d={'search':'| inputlookup misp_ioc_lookup.csv | head 5','output_mode':'json','exec_mode':'oneshot'}; r=requests.post('https://localhost:8088/services/search/jobs',auth=('admin','Hayyan@2024!'),verify=False,data=d,timeout=30); print(r.status_code); print(r.text[:900])"
```

## Minute 1:45-2:30 — Correlation Context

Say:
"Our detections consume misp_ioc_lookup.csv via inputlookup, then correlate against telemetry indexes and vulnerability posture for risk-adjusted alerts."

Show in Splunk Search:
```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type
```

```spl
index=linux_web [| inputlookup misp_ioc_lookup.csv | where ioc_type="ip-src" OR ioc_type="ip-dst" | rename ioc_value as clientip | fields clientip] | stats count by clientip
```

## Minute 2:30-3:00 — Close with Readiness

Say:
"The stack is hardened to canonical values, docs are aligned, and the IOC pipeline is deterministic. Final hardening docs, rotation procedure, and readiness checklist are in docs/final."

Point to:
- docs/final/FINAL_CORRECTED_DOCS.md
- docs/final/API_KEY_ROTATION_STEP.md
- docs/final/READINESS_CHECKLIST.md
