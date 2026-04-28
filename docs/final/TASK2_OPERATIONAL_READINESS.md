# Task 2 Operational Readiness Evidence

## Commercial SOC Story

Task 2 upgrades the Hayyan SOC lab into a threat-informed, exposure-aware defense loop:

- **MISP** provides known-bad indicators and internal intelligence.
- **Nuclei + Trivy** provide lightweight vulnerability and exposure findings suitable for a 16GB laptop.
- **Splunk** remains the central evidence plane for logs, scanner findings, IOC lookups, detections, dashboards, and audit events.
- **The AI SOC agent** enriches investigations with MISP context, vulnerability posture, retrospective hunting, and MISP event drafts.

This is intentionally lightweight. Nuclei and Trivy are used instead of OpenVAS/GVM because they provide realistic scan value without consuming several GB of RAM or turning the intern lab into a scanner operations project.

## Operational Evidence to Capture

Use this as the supervisor-facing evidence checklist after deployment.

| Evidence | Command or View | Pass Criteria |
|---|---|---|
| Splunk running | `docker compose -f docker-compose.splunk.yml ps` | Splunk container is healthy or running |
| MISP running | `docker compose -f docker-compose.misp.yml ps` | MISP, MySQL, and Redis containers are healthy or running |
| Task 2 indexes | `python scripts/validate_splunk.py` | `vuln_scans`, `misp_iocs`, and `ai_soc_audit` exist |
| HEC ingestion | `python scripts/validate_splunk.py` | Test events reach all three Task 2 indexes |
| MISP lookup export | `python scripts/misp_sync_splunk.py --dry-run` | IOC rows are returned, or an expected-empty reason is shown |
| MISP lookup in Splunk | `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type` | Lookup table is readable in Splunk |
| Rocky scanner deployment | `python scripts/deploy_rocky.py` | Scanner pack and timer deploy without hardcoded secrets |
| Manual scanner run | `python scripts/test_scanners.py` | Orchestrator runs and logs are generated |
| Scanner findings | `index=vuln_scans | stats count by scanner, severity` | Findings use `cveid`, `cvssscore`, `severity`, `target`, `service`, `remediation` |
| Agent audit | `index=ai_soc_audit | stats count by tool_name, status` | AI tool calls are visible |
| AI enrichment | Ask agent to investigate a suspicious IP/host | Report includes Threat Intelligence and Vulnerability Context |

## Five-Minute Demo Flow

1. **Show the architecture.** Explain that MISP says what is known-bad, Nuclei/Trivy show where the lab is exposed, Splunk shows what happened, and the AI agent reasons across all three.
2. **Validate Splunk and HEC.** Run `python scripts/validate_splunk.py` and show the three Task 2 indexes accepting test events.
3. **Sync threat intel.** Run `python scripts/misp_sync_splunk.py --dry-run`, then show `misp_ioc_lookup.csv` or the Splunk lookup search.
4. **Run scanner validation.** Run `python scripts/test_scanners.py`, then show `index=vuln_scans | stats count by scanner, severity`.
5. **Show AI enrichment.** Ask the AI agent: "Investigate 192.168.56.20 using MISP and vulnerability context." Show the Threat Intelligence, Vulnerability Context, and recommended actions.
6. **Close the loop safely.** Show that `create_misp_event` drafts a MISP event while `MISP_ALLOW_WRITE=false`, proving human approval is enforced.

## Final Readiness Gate

The Task 2 system is ready for internship presentation when:

- Splunk REST and HEC validate successfully.
- MISP API access works and the IOC lookup can be refreshed.
- Rocky scanner scripts deploy from env-driven settings.
- One scanner run produces normalized findings in `vuln_scans`.
- The AI agent can call MISP, vulnerability posture, and retrospective hunt tools.
- MISP write-back remains draft-only unless Mahmoud explicitly sets `MISP_ALLOW_WRITE=true`.

## Current Validation Snapshot

Validated on the local lab after the env-driven deployment cleanup and Rocky redeployment:

- **Splunk REST:** PASS. Splunk 10.2.2 reachable on `https://localhost:8088`.
- **Task 2 indexes:** PASS. `vuln_scans`, `misp_iocs`, and `ai_soc_audit` exist.
- **HEC ingestion:** PASS. Test events reached all three Task 2 indexes.
- **MISP IOC sync:** PASS. MISP returned IOC data and `data/misp_ioc_lookup.csv` was refreshed.
- **Splunk lookup refresh:** PASS. REST multipart upload was rejected by this Splunk lab, then controlled `outputlookup` fallback successfully refreshed `misp_ioc_lookup.csv`.
- **AI tool loop:** PASS. `check_splunk_health`, `get_vuln_posture`, `hunt_recent_misp_iocs`, and draft-only `create_misp_event` all completed successfully.
- **AI audit trail:** PASS. `ai_soc_audit` shows successful tool-call audit events for the validation run.
- **Rocky deployment:** PASS. Rocky is reachable over SSH, the scanner pack deploys to `/opt/hayyan-scan`, and `hayyan-scan.timer` is enabled successfully.
- **Rocky scanner execution:** PASS. `python scripts/test_scanners.py` completed successfully and the orchestrator produced normalized JSONL output on Rocky.
- **Normalized scanner pipeline:** PASS. The Rocky-side Nuclei target parsing and JSON normalization issues were fixed and redeployed successfully.
- **Demo finding generation:** IN PROGRESS. The latest real Rocky scan completed cleanly but produced zero Nuclei findings and zero Trivy findings, so no new production-style events were added to `index=vuln_scans` from that run.
