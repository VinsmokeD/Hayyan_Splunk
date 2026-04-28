# 3-Minute Demo Script

## Goal

Show a stable, end-to-end SOC loop: MISP intelligence, Rocky scanner exposure data, Splunk correlation, and AI/API enrichment.

## Minute 0:00-0:45 - Platform Health

Say:
"This lab is running a validated lightweight SOC stack: Splunk on 8080/8088/8086, MISP on 127.0.0.1:8443, Rocky as the authorized scanner, and the AI SOC API on port 8500."

Run:

```powershell
python scripts/validate_splunk.py
Invoke-RestMethod http://127.0.0.1:8500/api/health
Invoke-RestMethod http://127.0.0.1:8500/api/misp/health
```

Show:

- Splunk UI: http://localhost:8080
- Dashboard: http://localhost:8080/en-US/app/HayyanSOC/threat_dashboard
- MISP UI: https://127.0.0.1:8443
- AI API: http://localhost:8500

## Minute 0:45-1:30 - MISP IOC Sync

Say:
"IOC correlation is lookup-based. We sync published, IDS-ready MISP attributes into a Splunk lookup CSV so detections and hunts can use fast `inputlookup` joins."

Run:

```powershell
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
```

Show in Splunk:

```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type | sort -count
```

Expected: 4,995 IOCs in the current lab snapshot.

## Minute 1:30-2:15 - Vulnerability Scanner Pipeline

Say:
"Rocky is the authorized scanner node. For demo speed, the validation profile uses Trivy against a controlled vulnerable dependency fixture and pushes real CVE findings to Splunk."

Run:

```powershell
python scripts/deploy_rocky.py
python scripts/test_scanners.py
```

Show in Splunk:

```spl
index=vuln_scans scanid="run-20260428-171022"
| stats count by scanner, severity, target
| sort -count
```

Expected: 46 Trivy findings, including 6 critical and 20 high.

## Minute 2:15-2:45 - Exposure-Aware API Enrichment

Run:

```powershell
Invoke-RestMethod "http://127.0.0.1:8500/api/vuln-posture?target=192.168.56.20&severity=high"
```

Say:
"The AI/API layer can now see host exposure before it reasons about alerts. This is what turns the SOC from reactive monitoring into exposure-aware triage."

## Minute 2:45-3:00 - Safe Closed Loop

Say:
"The loop is intentionally safe. Scanner findings and agent investigations can draft or prepare MISP context, but live MISP write-back stays disabled until Mahmoud explicitly sets `MISP_ALLOW_WRITE=true`."

Point to:

- `docs/final/TASK2_OPERATIONAL_READINESS.md`
- `docs/final/READINESS_CHECKLIST.md`
- `docs/setup/ROCKY_SCANNER_SETUP.md`
