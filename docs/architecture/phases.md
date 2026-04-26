# Hayyan SOC Lab — Phase Roadmap

This is the single source of truth for project phase status.
Reference alongside `git log` to verify what is done.

---

## PHASE 1: Lab Infrastructure [COMPLETE]
**Goal:** Stand up Splunk + Rocky + DC01 with real log forwarding.
**Acceptance:** All indexes have live events. Alerts fire on real activity.
**Status:** ✅ COMMITTED

---

## PHASE 2: AI SOC Agent Foundation [COMPLETE]
**Goal:** Production-ready ReAct agent with Splunk tools, multi-provider LLM, Streamlit UI.
**Acceptance:** Agent investigates a live alert end-to-end and produces a markdown report.
**Status:** ✅ COMMITTED

---

## PHASE 3: Threat-Informed Defense Layer [IN PROGRESS]
**Goal:** Transform the SOC from reactive monitoring to a closed-loop threat-informed system integrating MISP, Nuclei, Trivy, and an AI audit trail.
**Acceptance:** A live demo shows rogue scan detected → MISP IOC match → AI agent produces a report with Threat Intel + Vulnerability Context sections → MISP event created via HITL.

### Phase 3.1 — MISP Base Layer & Splunk Threat Intel Layer
```
PHASE 3.1: MISP + Splunk Intel Integration
Goal: Deploy MISP, configure feeds, integrate IOCs into Splunk.
Acceptance: Query a known-bad IOC via query_misp_ioc and receive MISP hit data.
Files:
  - docker-compose.misp.yml (verify)
  - scripts/misp_setup.sh (feed config via MISP API)
  - scripts/misp_sync_splunk.py (IOC lookup CSV export)
  - splunk_config/indexes.conf (confirm all indexes)
  - splunk_config/misp_savedsearches.conf (IOC detection searches)
  - docs/setup/MISP_SETUP.md
Estimated tokens: ~300 lines
Dependencies: Docker running on host
```
**Status:** ✅ COMMITTED

### Phase 3.2 — Rocky Linux Scanner Pack
```
PHASE 3.2: Rocky Scanner Infrastructure
Goal: Automated vulnerability scanning from Rocky with normalized findings in Splunk.
Acceptance: vulnscans index has JSON events with standard schema after a scan run.
Files:
  - scripts/rocky/targets.yaml
  - scripts/rocky/nuclei-web.sh
  - scripts/rocky/trivy-fs.sh
  - scripts/rocky/normalize.py
  - scripts/rocky/push_splunk.py
  - scripts/rocky/push_misp.py
  - scripts/rocky/orchestrator.sh
  - systemd/hayyan-scan.service
  - systemd/hayyan-scan.timer
  - docs/setup/ROCKY_SCANNER_SETUP.md
Estimated tokens: ~380 lines
Dependencies: Phase 3.1 complete (HEC token configured)
```
**Status:** ✅ COMMITTED

### Phase 3.3 — AI Agent Audit Layer + Realism Simulation
```
PHASE 3.3: Agent Audit + Rogue Scan Simulation
Goal: Log every agent tool call to aisocaudit index. Add authorized vs rogue scan demo.
Acceptance: aisocaudit index has entries after an investigation. Rogue scan triggers alert.
Files:
  - soc_agents/tools/audit_tools.py
  - soc_agents/agents/soc_graph.py (wire audit)
  - scripts/rocky/rogue_scan_sim.sh
Estimated tokens: ~200 lines
Dependencies: Phase 3.2 complete
```
**Status:** ✅ COMMITTED

### Phase 3.4 — SOC Value Layer (Detections + Dashboard + Noise)
```
PHASE 3.4: Risk-Adjusted Detections + Dashboard + Benign Noise
Goal: Risk-adjusted alerts, threat dashboard, background noise for realism.
Acceptance: Dashboard shows Threat Intel, Vuln Heatmap, IOC Match Timeline panels.
Files:
  - splunk_config/risk_adjusted_alerts.conf
  - splunk_config/threat_dashboard.xml
  - scripts/noise_generator.py
Estimated tokens: ~350 lines
Dependencies: Phase 3.3 complete
```
**Status:** ✅ COMMITTED

---

## PHASE 4: Replay & Debrief UI Integration [PLANNED]
**Goal:** Integrate scanner findings + IOC hits + AI assessments onto the CyberSim kill-chain timeline for replay/debrief.
**Acceptance:** Debrief view shows scan → IOC hit → detection → AI report as a chronological story.
**Status:** 🔲 PLANNED

## PHASE 5: Retrospective Threat Hunting [PLANNED]
**Goal:** Weekly scheduled Splunk search pulls fresh MISP IOCs and hunts historical logs.
**Acceptance:** Hunt finds at least one simulated IOC match in historical index.
**Status:** 🔲 PLANNED
