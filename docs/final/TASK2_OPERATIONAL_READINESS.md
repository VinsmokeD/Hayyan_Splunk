# Task 2 Operational Readiness Evidence

## Commercial SOC Story

Task 2 upgrades the Hayyan SOC lab into a threat-informed, exposure-aware defense loop:

- **MISP** provides known-bad indicators and internal intelligence.
- **Nuclei + Trivy** provide lightweight vulnerability and exposure findings suitable for a 16GB laptop.
- **Splunk** remains the central evidence plane for logs, scanner findings, IOC lookups, detections, dashboards, and audit events.
- **The AI SOC agent** enriches investigations with MISP context, vulnerability posture, retrospective hunting, and MISP event drafts.

This is intentionally lightweight. Nuclei and Trivy are used instead of OpenVAS/GVM because they provide realistic scan value without consuming several GB of RAM or turning the intern lab into a scanner operations project.

## Current Validation Snapshot

Validated on April 28, 2026 in the local lab:

| Area | Status | Evidence |
|---|---|---|
| MISP IOC dry run | PASS | `python scripts/misp_sync_splunk.py --dry-run` fetched 5,000 attributes and deduplicated them to 4,995 unique IOCs. |
| Full MISP IOC sync | PASS | `python scripts/misp_sync_splunk.py` wrote `data/misp_ioc_lookup.csv` and refreshed Splunk using chunked `outputlookup` fallback. |
| Splunk lookup readable | PASS | `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type` returned 4,995 IOCs. |
| Rocky scanner deployment | PASS | `python scripts/deploy_rocky.py` verified Nuclei and Trivy, deployed the scanner pack, wrote `splunkhec.env`, and enabled `hayyan-scan.timer`. |
| Scanner pipeline | PASS | `python scripts/test_scanners.py` ran a fast Trivy validation scan and pushed 46 findings to Splunk HEC. |
| Vulnerability findings | PASS | Scan `run-20260428-171022` produced 6 critical, 20 high, and 20 medium Trivy findings in `index=vuln_scans`. |
| MISP write safety | PASS | Scanner MISP mirroring skipped live writes because `MISP_ALLOW_WRITE=false`. |
| API health | PASS | `http://localhost:8500/api/health` returned `status=ok` and Splunk connected. |
| API MISP health | PASS | `http://localhost:8500/api/misp/health` returned MISP connected with version `2.5.33.1`. |
| API vulnerability posture | PASS | `http://localhost:8500/api/vuln-posture?target=192.168.56.20&severity=high` returned Rocky with max CVSS 9.8, 6 critical, and 25 high findings. |
| AI chat investigation | BLOCKED PENDING APPROVAL | Local `/api/chat` reached the API, but Groq returned `APIConnectionError`. Retrying outside the sandbox was rejected because it would send SOC context to an external provider without explicit approval. |

## Evidence Commands

Run these from the project root:

```powershell
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
python scripts/deploy_rocky.py
python scripts/test_scanners.py
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500
```

Useful Splunk checks:

```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type | sort -count
```

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

```spl
index=ai_soc_audit
| stats count by tool_name, status
| sort -count
```

## Demo Notes

The fast scanner validation uses a controlled vulnerable dependency fixture at `/opt/hayyan-scan/demo-fixtures/vulnerable-python`. Trivy scans it as a real dependency manifest and produces real CVE findings. This gives a reliable under-five-minute demo without weakening the actual Rocky host or relying on random vulnerable services.

The scheduled `hayyan-scan.timer` remains the operational path for full scans. The validation script uses:

```powershell
ROCKY_TEST_SCAN_ARGS=--trivy
ROCKY_TEST_SCAN_PROFILE=demo
```

## Five-Minute Demo Flow

1. Show `python scripts/validate_splunk.py` and the three Task 2 indexes.
2. Run `python scripts/misp_sync_splunk.py --dry-run`, then `python scripts/misp_sync_splunk.py`.
3. Show `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type`.
4. Run `python scripts/deploy_rocky.py`, then `python scripts/test_scanners.py`.
5. Show `index=vuln_scans scanid="run-20260428-171022" | stats count by scanner, severity, target`.
6. Start the API with `python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500`.
7. Open `http://localhost:8500` and verify `/api/health`, `/api/misp/health`, and `/api/vuln-posture?target=192.168.56.20&severity=high`.
8. Test chat only after explicitly approving external LLM provider use for the prompt: "Investigate 192.168.56.20 using MISP and vulnerability context."

## Final Readiness Gate

Task 2 is operationally ready when:

- Splunk REST and HEC validate successfully.
- MISP API access works and the IOC lookup refreshes into Splunk.
- Rocky scanner scripts deploy from env-driven settings.
- One scanner run produces normalized findings in `vuln_scans`.
- The API exposes health, MISP health, and vulnerability posture successfully.
- MISP write-back remains draft-only or disabled unless Mahmoud explicitly sets `MISP_ALLOW_WRITE=true`.
- AI chat is tested only with explicit approval for sending lab context to the selected external LLM provider.
