# Hayyan SOC Lab - Phase Roadmap

This is the single source of truth for project phase status. Reference alongside `git log` and the validation docs in `docs/final`.

## Phase 1: Lab Infrastructure [Complete]

Goal: Stand up Splunk, Rocky Linux, and DC01 with real log forwarding.

Acceptance: All core indexes have live events and alerts fire on real activity.

Status: Complete.

## Phase 2: AI SOC Agent Foundation [Complete]

Goal: Production-ready single ReAct SOC agent with Splunk tools, multi-provider LLM routing, and API/UI surface.

Acceptance: Agent can investigate Splunk evidence, use tool calls, and produce analyst-facing output when a provider is available.

Status: Complete, with external LLM calls requiring explicit approval when lab context may leave the machine.

## Phase 3: Threat-Informed Defense Layer [Operationally Validated]

Goal: Transform the SOC from reactive monitoring to a closed-loop threat-informed system integrating MISP, Nuclei, Trivy, Splunk HEC, and AI audit telemetry.

Acceptance: A live demo shows MISP IOC sync, Rocky scanner findings in Splunk, exposure-aware API enrichment, and safe MISP write-back control.

Status: Operationally validated on April 28, 2026.

### Phase 3.1: MISP + Splunk Intel Integration

Goal: Deploy MISP, configure feeds, export IOCs into Splunk, and make IOC data usable for correlation and retrospective hunting.

Validated evidence:

- `python scripts/misp_sync_splunk.py --dry-run` fetched 5,000 MISP attributes.
- Deduplication produced 4,995 unique IOCs.
- `python scripts/misp_sync_splunk.py` wrote `data/misp_ioc_lookup.csv`.
- Large lookup refresh works through chunked `outputlookup` fallback.
- Splunk search `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type` returns IOC counts.

Key files:

- `docker-compose.misp.yml`
- `scripts/misp_setup.sh`
- `scripts/misp_sync_splunk.py`
- `splunk_config/risk_adjusted_alerts.conf`
- `docs/setup/MISP_SETUP.md`

Status: Validated.

### Phase 3.2: Rocky Scanner Infrastructure

Goal: Run authorized vulnerability scanning from Rocky and push normalized findings to Splunk.

Validated evidence:

- `python scripts/deploy_rocky.py` connects to Rocky, verifies Nuclei/Trivy, deploys scanner files, writes `splunkhec.env`, and enables `hayyan-scan.timer`.
- `python scripts/test_scanners.py` runs the fast Trivy validation profile.
- Scan `run-20260428-171022` produced 46 normalized Trivy findings.
- Splunk HEC accepted all 46 findings into `index=vuln_scans`.
- Severity distribution: 6 critical, 20 high, 20 medium.

Key files:

- `scripts/rocky/targets.yaml`
- `scripts/rocky/nuclei-web.sh`
- `scripts/rocky/trivy-fs.sh`
- `scripts/rocky/normalize.py`
- `scripts/rocky/push_splunk.py`
- `scripts/rocky/push_misp.py`
- `scripts/rocky/orchestrator.sh`
- `scripts/rocky/demo-fixtures/vulnerable-python/requirements.txt`
- `systemd/hayyan-scan.service`
- `systemd/hayyan-scan.timer`
- `docs/setup/ROCKY_SCANNER_SETUP.md`

Status: Validated.

### Phase 3.3: Agent Audit + Safe MISP Write-Back

Goal: Log AI tool use and preserve human approval for MISP write actions.

Validated evidence:

- `index=ai_soc_audit | stats count by tool_name, status` returns tool-call audit events.
- Scanner-side MISP mirroring skips live writes when `MISP_ALLOW_WRITE=false`.
- Agent-side MISP event creation remains draft-only unless write approval is explicitly enabled.

Status: Validated.

### Phase 3.4: SOC Value Layer

Goal: Risk-adjusted detections, threat dashboard, background noise, and exposure-aware triage.

Validated evidence:

- `vuln_scans` contains normalized vulnerability fields for risk-aware correlation.
- `misp_ioc_lookup.csv` is available to lookup-based detections and hunts.
- API endpoint `/api/vuln-posture?target=192.168.56.20&severity=high` returns Rocky exposure context with max CVSS 9.8.

Status: Validated, with dashboard visual review still recommended before presentation.

## Phase 4: Replay and Debrief UI Integration [Planned]

Goal: Integrate scanner findings, IOC hits, and AI assessments onto the CyberSim kill-chain timeline for replay/debrief.

Acceptance: Debrief view shows scan, IOC hit, detection, and AI report as a chronological story.

Status: Planned.

## Phase 5: Retrospective Threat Hunting [Implemented]

Goal: Scheduled and agent-driven Splunk hunts compare newly synced MISP IOCs against historical logs.

Acceptance: `hunt_recent_misp_iocs` can search web, DNS, Sysmon hash, and Windows evidence for IOCs imported in the last 24 hours.

Key files:

- `soc_agents/tools/splunk_tools.py`
- `soc_agents/agents/soc_graph.py`
- `scripts/misp_sync_splunk.py`
- `splunk_config/risk_adjusted_alerts.conf`

Status: Implemented. Full chat-based validation requires explicit approval before sending lab context to the configured external LLM provider.
