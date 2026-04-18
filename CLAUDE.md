# Hayyan Horizons SOC Lab — Claude Code Context

## Project Overview
A full Splunk SIEM home lab built on a single Windows 11 laptop (16GB RAM) using VMware Workstation.
Phase 2 builds a **Production-Ready AI SOC Analyst** (single ReAct agent architecture) powered by Groq or Gemini. It acts as an autonomous Tier-1 analyst — watching Splunk alerts, investigating across all indexes, mapping to MITRE ATT&CK, and producing incident reports.

Built by **Mahmoud**, SOC Intern at Hayyan Horizons.

**Key reference implementation:** Omar Santos (Cisco / DEF CON Red Team Village) — `santosomar/AI-agents-for-cybersecurity` on GitHub. Study this repo for working LangGraph + MCP + cybersecurity patterns before writing any agent code.

---

## Infrastructure

| Component | Details |
|---|---|
| **Host OS** | Windows 11 (16GB RAM) |
| **Hypervisor** | VMware Workstation |
| **Network** | VMnet2 host-only: `192.168.56.0/24` |
| **Splunk Enterprise** | Docker on host, UI port `8080`, indexer `9997`, REST API `8089` |
| **Rocky Linux 10 VM** | `192.168.56.20` (also NAT: `192.168.229.100` via ens160) |
| **Windows Server 2022** | `192.168.56.10` — DC01.hayyan.local |
| **Splunk Password** | `Hayyan@2024!` |

---

## Active Directory

- **Domain:** `hayyan.local` | NetBIOS: `HAYYAN`
- **DC:** `DC01.hayyan.local` at `192.168.56.10`
- **Domain Mode:** Windows2016Domain
- **OUs:** `SOC_Team`, `Hayyan_Staff`
- **Groups:** `SOC_Admins`
- **Users:** `akhalil`, `snasser`, `svc_it`, `jdoe`, `jsmith`
- **SPN (Kerberoasting target):** `HTTP/webserver.hayyan.local` on `svc_it`

---

## Splunk Indexes

| Index | Source | Events |
|---|---|---|
| `linux_audit` | auditd kernel events | ~12,863 |
| `linux_web` | Nginx access/error logs | — |
| `linux_secure` | SSH/PAM auth | — |
| `windows_events` | AD Security/System/Application | — |
| `sysmon` | Sysmon ETW XML (DC01) | — |
| **Total** | | **27,341+** |

---

## Splunk Forwarders

### Rocky Linux UF
- Version: `10.2.2` | Path: `/opt/splunkforwarder`
- Service: `SplunkForwarder`
- Forwards to: `192.168.56.1:9997`
- Monitors: nginx logs, `/var/log/secure`, auditd logs

### Windows UF (DC01)
- Version: `10.2.2` | Path: `C:\Program Files\SplunkUniversalForwarder`
- Runs as: `LocalSystem` (required for Sysmon channel access)
- Monitors: Security, System, Application, Sysmon channels (`renderXml=true`)

---

## Rocky Linux Hardening

- **SELinux:** Enforcing — nginx logs keep `httpd_log_t`, splunkfwd access via `setfacl`
- **Firewalld:** Drop zone (stealthy — no ping response)
- **SSH:** `PermitRootLogin no`, `MaxAuthTries 3`, `AllowTcpForwarding no`, `X11Forwarding no`
- **Fail2Ban:** `maxretry=3`, `bantime=1h`
- **auditd rules:** `identity_changes`, `ssh_config_changes`, `webserver_logs`, `command_exec`

---

## Sysmon (DC01)

- Version: `v15.20` | Config: SwiftOnSecurity
- Log channel: `Microsoft-Windows-Sysmon/Operational`
- Format in Splunk: XML — use this rex for CommandLine:
  ```spl
  rex field=_raw "Name='CommandLine'>(?<cmd>[^<]+)"
  ```

---

## Configured Splunk Alerts

| Alert | Schedule | Trigger | Severity |
|---|---|---|---|
| Password Spray Detected | `*/5 * * * *` | EventCode=4625, count > 5 | High |
| Web Scanner Detected | `*/5 * * * *` | Nginx 404s > 15 per IP | High |
| Linux Identity Change | `*/10 * * * *` | auditd key=identity_changes | Medium |

All alerts use **Add to Triggered Alerts** with throttle enabled.

---

## Known Issues & Fixes

| Issue | Fix |
|---|---|
| auditd can't be restarted manually | Use `augenrules --load` instead |
| auditd future timestamps (year 2038) | Cosmetic — fix with `timedatectl` / `chronyc` |
| nginx SELinux relabeling breaks things | Use `setfacl` for splunkfwd access, don't relabel |
| Docker volume mounts break Splunk perms | Run Splunk container without volume mounts |
| Port 8000 taken by Docker Desktop | Map `8080:8000` in Docker run command |
| Sysmon errorCode=5 in UF logs | Run SplunkForwarder as LocalSystem |

---

# Phase 2 — LangGraph Multi-Agent AI SOC System

## Vision

An autonomous AI SOC Tier-1 analyst that:
1. Watches Splunk for fired alerts every 60 seconds
2. Triages each alert (false positive vs. real threat)
3. Investigates by pivoting across all indexes using natural language → SPL
4. Enriches IoCs with MITRE ATT&CK technique mapping via RAG
5. Produces a polished markdown incident report
6. Proposes response actions — but **always pauses for Mahmoud's approval** before executing anything

---

## Design Principles

1. **Human-in-the-loop for any write action.** AI reads freely, but blocking/disabling/deleting always pauses for Mahmoud's explicit approval.
2. **Natural language → SPL.** Agents never hand-write SPL. They describe what they want in plain English, and the Splunk MCP server translates and executes it.
3. **SPL guardrails.** Every generated SPL query passes validation before execution. No `| delete`, no unbounded time ranges, no destructive commands.
4. **Evidence-driven.** Every finding must cite the specific Splunk events (index, `_time`, `_raw` snippet) that support it. No hallucinated conclusions.
5. **MITRE ATT&CK mapped.** Every confirmed incident is tagged with technique IDs (T1110, T1078, T1595, etc).
6. **Stateful.** LangGraph SQLite checkpoints every node — investigations survive restarts and can be audited.
7. **Cheap by default.** Gemini Flash for high-volume triage, Gemini Pro only for final report synthesis.

---

## Stack

| Layer | Tool | Notes |
|---|---|---|
| LLM | `gemini-2.5-flash` + `gemini-2.5-pro` | Flash for triage/SPL gen; Pro for correlation + reports |
| Orchestration | **LangGraph** | State machine, checkpoints, HITL interrupts |
| Agent framework | **LangChain** | Tool bindings, prompt templates, output parsers |
| Splunk bridge | **`livehybrid/splunk-mcp`** (primary) + **`splunk-sdk`** fallback | MCP runs as local Python process talking to Splunk REST on 8089 |
| MCP ↔ LangGraph | **`langchain-mcp-adapters`** | `MultiServerMCPClient` auto-converts MCP tools → LangChain tools |
| Knowledge base | **ChromaDB** (local, on-disk) | MITRE ATT&CK + SOC playbooks + past incidents |
| Embeddings | **`sentence-transformers/all-MiniLM-L6-v2`** | Free, local, no API calls |
| State persistence | **`langgraph.checkpoint.sqlite`** | SQLite checkpointer, survives restarts |
| Observability | **LangSmith** (free tier) | Trace every agent step, debug failures |
| UI | **Streamlit** | Dashboard to watch agents work + approve response actions |
| Audit trail | **Splunk HEC** | Agents log their own actions to `ai_soc_audit` index |

---

## Splunk MCP Setup (Critical — Read Before Writing Any Agent Code)

### Why `livehybrid/splunk-mcp` (not the official Splunkbase app)
The official Splunk MCP Server (App ID 7931) is designed for Splunk Cloud and exposes itself at `https://<host>:8089/services/mcp`. It may or may not work with the Docker-based Splunk Enterprise in this lab. The `livehybrid/splunk-mcp` project runs as a standalone local Python process that talks to Splunk's REST API — it definitely works with on-prem/Docker Splunk.

**Test the official one first** (it's better long-term), **fall back to livehybrid** if it doesn't connect.

### How the MCP connection works

```
Gemini LLM
    │  (tool call in natural language)
    ▼
langchain-mcp-adapters (MultiServerMCPClient)
    │  (MCP protocol over SSE/HTTP)
    ▼
livehybrid/splunk-mcp server  (localhost:8000)
    │  (Splunk REST API calls)
    ▼
Splunk Enterprise  (192.168.56.1:8089)
    │  (SPL query execution)
    ▼
Returns JSON results → back up the chain to the agent
```

### Starting the MCP server
```bash
# In a dedicated terminal — keep this running the entire time
cd splunk-mcp
poetry run python splunk_mcp.py sse
# or: SERVER_MODE=api poetry run uvicorn splunk_mcp:app --host 0.0.0.0 --port 8000
```

### Connecting LangChain to the MCP server
```python
from langchain_mcp_adapters.client import MultiServerMCPClient

async with MultiServerMCPClient({
    "splunk": {
        "transport": "http",
        "url": "http://localhost:8000/sse",
    }
}) as client:
    tools = client.get_tools()  # auto-discovers all Splunk tools
    # tools now contains: search_oneshot, validate_spl, get_indexes,
    # get_saved_searches, run_saved_search, search_export
```

### Binding Splunk MCP tools to Gemini
```python
from langchain_google_genai import ChatGoogleGenerativeAI

# This is the core pattern — Gemini with Splunk tools bound
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
splunk_llm = llm.bind_tools(tools)  # tools from MultiServerMCPClient above

# Now the agent can investigate in plain English — MCP handles the SPL
response = splunk_llm.invoke(
    "Find all failed SSH logins in linux_secure index from the last hour, "
    "grouped by source IP and username"
)
```

---

## Agent Roster

### 1. `AlertIngestAgent`
- **Job:** Poll Splunk REST `/services/alerts/fired_alerts` every 60s. Dedupe by alert ID. Push each new alert as a new LangGraph thread.
- **Tools:** `splunk_list_fired_alerts`, `splunk_get_alert_details` (via SDK, not MCP — more reliable for alert polling)
- **Model:** None — pure deterministic Python
- **Output:** `alert_id`, `alert_raw` dict pushed into `SOCState`
- **Handoff:** → `TriageAgent`

### 2. `TriageAgent`
- **Job:** Read the alert. Answer three questions: Is this a known false positive? Is the affected entity (IP/user) high-value? Has this pattern appeared recently? Decide: close or escalate.
- **Tools:** `splunk_search` (recent history for this entity), `check_ip_internal` (is IP in 192.168.56.0/24?), `lookup_user_in_ad` (is user in SOC_Admins? is it a service account?)
- **Model:** `gemini-2.5-flash`
- **Output:** `TriageVerdict` pydantic model: `{severity, confidence, reasoning, next_action}`
- **Handoff:** → `SupervisorAgent`

**Triage prompt template:**
```
You are a SOC Tier-1 analyst. You have received the following alert:

Alert: {alert_name}
Trigger: {alert_details}
Time: {alert_time}

Use your tools to investigate the following:
1. Is the source IP internal (192.168.56.0/24) or external?
2. Is the affected user a service account or member of SOC_Admins?
3. Has this exact pattern (same IP + user + event type) triggered in the last 24h?

Based on your findings, classify this alert as:
- FALSE_POSITIVE: clear benign explanation exists
- LOW: suspicious but low risk, log and monitor
- MEDIUM: investigate further
- HIGH: escalate immediately to InvestigatorAgent

Return a JSON object: {severity, confidence (0-1), reasoning, next_action}
```

### 3. `InvestigatorAgent`
- **Job:** Deep-dive the escalated alert. Follow the 5-step investigation pattern (see below). Pivot across indexes. Build a timeline. Identify affected assets and IoCs.
- **Tools:** `splunk_search`, `validate_spl`, `get_sysmon_processes`, `get_auditd_events`, `rag_search_playbook`
- **Model:** `gemini-2.5-flash` for SPL generation; `gemini-2.5-pro` for multi-step correlation reasoning
- **Output:** `Investigation` pydantic model: `{timeline, affected_assets, iocs, pivot_findings}`
- **Handoff:** → `ThreatIntelAgent`

**The 5-Step Investigation Pattern (from Omar Santos / becomingahacker.org)**

Every investigation the `InvestigatorAgent` runs must follow this exact sequence:

```
Step 1 — UNDERSTAND
  Ask: "What indexes, fields, and sourcetypes are relevant to this alert?"
  Action: Query get_indexes, check available fields for relevant index
  Output: Confirm which of {linux_audit, linux_web, linux_secure,
          windows_events, sysmon} contains the signal

Step 2 — GENERATE SPL
  Ask: "What natural language question do I need answered?"
  Action: Describe the question in plain English → MCP generates SPL
  Rule: ALWAYS call validate_spl before executing any generated query
  Example questions:
    - "Show failed SSH logins in linux_secure grouped by source IP,
       last 2 hours, more than 3 failures"
    - "Find Sysmon Event ID 1 process creation where parent is cmd.exe
       or powershell.exe on DC01 in the last hour"
    - "List auditd events with key=identity_changes in the last 24 hours
       with the command that triggered them"
    - "Show nginx 404 errors from linux_web grouped by client IP,
       last 30 minutes, more than 10 hits"
    - "Find EventCode 4625 in windows_events grouped by TargetUserName
       and IpAddress, last hour, count > 5"

Step 3 — EXECUTE
  Action: Run validated SPL via splunk_search tool
  If results empty: broaden time range or adjust filter, re-validate, re-run
  If results > 1000 rows: use search_export for streaming

Step 4 — ANALYZE
  Ask: "What does this tell me? Are there anomalies? What's the pattern?"
  Action: Interpret results. Look for: unusual hours, new IPs, repeated
          failures, lateral movement indicators, privilege escalation signs
  Cross-index pivot: if windows_events shows suspicious user →
    check sysmon for process creation by that user →
    check linux_secure for SSH attempts from same IP

Step 5 — REPORT FINDINGS
  Action: Compile into structured Investigation object:
    - Timeline of events (chronological, with index + _time + _raw snippet)
    - Affected assets (IPs, hostnames, usernames)
    - IoCs (IPs, hashes, domains, commands)
    - Confidence level and reasoning
```

**Index-specific investigation examples:**

```python
# Password spray investigation
"Show EventCode 4625 failed logins in windows_events index, last 1 hour,
 grouped by TargetUserName and IpAddress, where count > 5"

# Web scanner investigation  
"Show 404 errors in linux_web nginx access logs, last 30 minutes,
 grouped by clientip, sorted by count descending"

# Linux identity change investigation
"Find auditd events with key=identity_changes in linux_audit,
 last 24 hours, show the syscall and command that triggered it"

# SSH brute force investigation
"Show failed authentication events in linux_secure,
 last 2 hours, grouped by source address, count > 3"

# Post-exploitation recon (Sysmon)
"Find Sysmon EventCode=1 process creation events in sysmon index,
 last hour, where CommandLine contains net or whoami or ipconfig"
```

### 4. `ThreatIntelAgent`
- **Job:** Take IoCs from the Investigator (IPs, usernames, commands, file hashes). Look up against local lists. Map TTPs to MITRE ATT&CK via RAG over the MITRE knowledge base. Tag with technique IDs.
- **Tools:** `lookup_ioc_local`, `mitre_attack_rag_search`, `check_abuseipdb` *(optional — add key later)*
- **Model:** `gemini-2.5-flash`
- **Output:** `ThreatIntel` pydantic model: `{mitre_techniques, ioc_reputation, confidence}`
- **Handoff:** → `SupervisorAgent`

**MITRE ATT&CK mappings for known lab alert types:**

| Alert Type | MITRE Technique | ID |
|---|---|---|
| Password spray (4625 burst) | Brute Force: Password Spraying | T1110.003 |
| Web scanner (404 spike) | Active Scanning | T1595.002 |
| Linux identity change | OS Credential Dumping / Account Manipulation | T1003 / T1098 |
| SSH brute force | Brute Force: Password Guessing | T1110.001 |
| AD recon (4720/4728/4769) | Account Discovery / Kerberoasting | T1087 / T1558.003 |
| Sysmon process recon | System Information Discovery | T1082 |

### 5. `ReportAgent`
- **Job:** Synthesize all state into a polished, analyst-ready incident report. Always use `gemini-2.5-pro` — this is the one place quality matters most.
- **Tools:** `write_incident_report`, `splunk_hec_send` (log to `ai_soc_audit`)
- **Model:** `gemini-2.5-pro`
- **Output:** Markdown incident report

**Incident report structure:**
```markdown
# Incident Report — {alert_name} — {timestamp}

## Executive Summary
[2-3 sentences. What happened, who was affected, severity, recommended action.]

## Timeline of Events
| Time | Index | Event | Significance |
|------|-------|-------|--------------|
| ...  | ...   | ...   | ...          |

## Affected Assets
- **IPs:** ...
- **Hostnames:** ...
- **Users:** ...

## Indicators of Compromise (IoCs)
- IP: x.x.x.x — [reputation]
- User: username — [context]
- Command: ... — [why suspicious]

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|-----|
| ...    | ...       | ... |

## Evidence (Splunk Events)
[Specific _raw snippets from Splunk with index and _time cited]

## Recommendations
1. [Immediate action]
2. [Short-term hardening]
3. [Detection improvement]

## AI Confidence
Triage confidence: X% | Investigation confidence: Y%
```

### 6. `ResponseAgent` — HUMAN-IN-THE-LOOP REQUIRED
- **Job:** Propose response actions. Present them clearly in Streamlit. **Never execute without Mahmoud clicking Approve.**
- **Tools:** `propose_disable_ad_user`, `propose_block_ip_firewalld`, `execute_approved_action`
- **Model:** `gemini-2.5-pro`
- **LangGraph:** Uses `interrupt_before=["execute_approved_action"]` — graph hard-stops here. Streamlit shows the proposal. Mahmoud clicks Approve or Reject. Only then does graph resume.
- **NEVER** auto-execute. **NEVER** target `SOC_Admins` accounts. **NEVER** block `192.168.56.0/24` without dual confirmation.

### 7. `SupervisorAgent` (the router)
- **Job:** Conditional edge logic. Reads state after each agent and routes to the next node. Start with pure Python rules — no LLM needed here.
- **Model:** None (Python rules). Upgrade to `gemini-2.5-flash` routing later only if rules get complex.

**Routing rules:**
```python
def supervisor_route(state: SOCState) -> str:
    if state["current_agent"] == "triage":
        verdict = state["triage_verdict"]
        if verdict.next_action == "FALSE_POSITIVE":
            return "close"
        elif verdict.severity in ["MEDIUM", "HIGH"]:
            return "investigator"
        else:
            return "close"

    if state["current_agent"] == "investigator":
        return "threat_intel"

    if state["current_agent"] == "threat_intel":
        return "report"

    if state["current_agent"] == "report":
        if state["proposed_actions"]:
            return "response"
        return "close"
```

---

## Graph Topology

```
                  ┌────────────────────┐
                  │  AlertIngestAgent  │  (scheduled, every 60s)
                  └──────────┬─────────┘
                             │
                             ▼
                  ┌────────────────────┐
                  │    TriageAgent     │
                  └──────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
           false positive         escalate
                 │                       │
                 ▼                       ▼
           ┌─────────┐         ┌──────────────────┐
           │ CLOSED  │         │ InvestigatorAgent│
           │ (log)   │         └────────┬─────────┘
           └─────────┘                  │
                                        ▼
                              ┌──────────────────┐
                              │ ThreatIntelAgent │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │   ReportAgent    │
                              └────────┬─────────┘
                                       │
                          needs response action?
                           │                   │
                          yes                  no
                           │                   │
                           ▼                   ▼
                ┌─────────────────┐      ┌─────────┐
                │  ResponseAgent  │──────│ CLOSED  │
                │ ⚠ HITL pause ⚠ │      │ (log)   │
                └─────────────────┘      └─────────┘
```

---

## State Schema

```python
from typing import TypedDict, Optional, Annotated
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

class TriageVerdict(TypedDict):
    severity: str          # FALSE_POSITIVE | LOW | MEDIUM | HIGH
    confidence: float      # 0.0 to 1.0
    reasoning: str
    next_action: str

class Investigation(TypedDict):
    timeline: list[dict]          # [{time, index, event, significance}]
    affected_assets: dict         # {ips, hostnames, users}
    iocs: list[dict]              # [{type, value, context}]
    pivot_findings: list[str]     # cross-index correlations found
    spl_queries_run: list[str]    # audit trail of every SPL query executed

class ThreatIntel(TypedDict):
    mitre_techniques: list[dict]  # [{tactic, technique, id, confidence}]
    ioc_reputation: dict          # {ip/hash: {score, source}}
    confidence: float

class ProposedAction(TypedDict):
    action_type: str              # disable_user | block_ip | kill_process
    target: str
    justification: str
    risk: str                     # LOW | MEDIUM | HIGH
    approved: Optional[bool]      # None=pending, True=approved, False=rejected

class SOCState(TypedDict):
    alert_id: str
    alert_raw: dict
    triage_verdict: Optional[TriageVerdict]
    investigation: Optional[Investigation]
    threat_intel: Optional[ThreatIntel]
    report_markdown: Optional[str]
    proposed_actions: list[ProposedAction]
    approved_actions: list[ProposedAction]
    executed_actions: list[dict]
    messages: Annotated[list[BaseMessage], add_messages]
    current_agent: str
    error: Optional[str]
```

---

## Project Directory Layout

```
hayyan-ai-soc/
├── CLAUDE.md                        ← this file
├── README.md
├── .env                             ← never commit this
├── .env.example
├── pyproject.toml
├── requirements.txt
│
├── ai_soc/
│   ├── __init__.py
│   ├── config.py                    ← loads .env, all settings in one place
│   ├── state.py                     ← SOCState TypedDict + all pydantic models
│   │
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── build.py                 ← StateGraph assembly — nodes + edges
│   │   ├── supervisor.py            ← routing logic (Python rules first)
│   │   └── checkpointer.py          ← SQLite checkpointer setup
│   │
│   ├── agents/
│   │   ├── alert_ingest.py          ← polls /services/alerts/fired_alerts
│   │   ├── triage.py                ← fast Gemini Flash classification
│   │   ├── investigator.py          ← 5-step deep investigation
│   │   ├── threat_intel.py          ← MITRE RAG + IoC lookup
│   │   ├── report.py                ← Gemini Pro report synthesis
│   │   └── response.py              ← HITL action proposals
│   │
│   ├── tools/
│   │   ├── splunk_tools.py          ← wraps MCP tools + SDK fallback
│   │   ├── spl_guardrails.py        ← validates ALL generated SPL
│   │   ├── ad_tools.py              ← AD user lookup + propose disable
│   │   ├── firewall_tools.py        ← propose firewalld block
│   │   └── ioc_tools.py             ← local threat intel lookups
│   │
│   ├── knowledge/
│   │   ├── build_kb.py              ← ingest MITRE + playbooks → Chroma
│   │   ├── mitre/
│   │   │   └── enterprise-attack.json   ← download from MITRE GitHub
│   │   ├── playbooks/
│   │   │   ├── password_spray.md
│   │   │   ├── web_scanner.md
│   │   │   ├── ssh_brute_force.md
│   │   │   ├── linux_identity_change.md
│   │   │   └── ad_recon.md
│   │   └── chroma_db/               ← persistent vector store (gitignore this)
│   │
│   ├── prompts/
│   │   ├── triage.py                ← triage prompt template
│   │   ├── investigator.py          ← 5-step investigation prompt
│   │   ├── threat_intel.py
│   │   └── report.py                ← incident report prompt + structure
│   │
│   └── ui/
│       └── streamlit_app.py         ← dashboard + HITL approval UI
│
├── splunk-mcp/                      ← git clone livehybrid/splunk-mcp here
│   └── splunk_mcp.py
│
├── scripts/
│   ├── start_splunk_mcp.sh          ← starts livehybrid MCP server
│   ├── run_agent.py                 ← headless CLI entry point
│   ├── backfill_kb.py               ← rebuilds ChromaDB knowledge base
│   └── test_splunk_connection.py    ← verify MCP + SDK connectivity
│
├── tests/
│   ├── test_spl_guardrails.py       ← unit tests, no LLM needed
│   ├── test_triage_agent.py
│   └── test_investigator_agent.py
│
└── data/
    ├── checkpoints.sqlite           ← LangGraph state (gitignore)
    └── audit.log
```

---

## SPL Guardrails (spl_guardrails.py)

Every generated SPL query MUST pass this validation before execution. No exceptions.

```python
BLOCKED_COMMANDS = [
    "| delete",
    "| drop",
    "| outputlookup",   # whitelist specific ones if needed
    "| collect",
    "| sendemail",
    "| sendalert",
    "restart",
    "| script",
]

MAX_TIME_RANGE_DAYS = 7
MAX_SUBSEARCH_RESULTS = 50_000

def validate_spl(query: str) -> tuple[bool, str]:
    """Returns (is_valid, reason). Call before every splunk_search."""
    query_lower = query.lower()
    for cmd in BLOCKED_COMMANDS:
        if cmd in query_lower:
            return False, f"Blocked command detected: {cmd}"
    # Add time range check, subsearch depth check, etc.
    return True, "OK"
```

---

## Gemini Model Usage

| Task | Model | Reason |
|---|---|---|
| Alert triage | `gemini-2.5-flash` | Runs on every alert — latency and cost matter |
| SPL query generation | `gemini-2.5-flash` | Pattern-heavy, structured output |
| Cross-index correlation | `gemini-2.5-pro` | Multi-step reasoning needs quality |
| Incident report writing | `gemini-2.5-pro` | Final deliverable — quality matters most |
| Response action proposals | `gemini-2.5-pro` | High-stakes, one mistake = outage |
| Supervisor routing | None (Python rules) | Deterministic is better here |

---

## Knowledge Base (ChromaDB Collections)

1. **`mitre_attack`** — MITRE ATT&CK Enterprise matrix. Download `enterprise-attack.json` from `mitre/cti` GitHub repo.
2. **`soc_playbooks`** — Markdown runbooks for each alert type in this lab (5 files in `playbooks/` above).
3. **`past_incidents`** — Re-embed every closed incident report. Grows over time. Used for similarity search during triage.
4. **`splunk_spl_patterns`** — Known-good SPL templates for each index in this lab.

---

## Environment Variables (.env)

```bash
# Gemini — REQUIRED
GOOGLE_API_KEY=your_gemini_api_key_here

# Splunk REST API
SPLUNK_HOST=192.168.56.1
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=Hayyan@2024!
SPLUNK_SCHEME=https
VERIFY_SSL=false

# Splunk HEC (create token via Settings → Data Inputs → HTTP Event Collector)
SPLUNK_HEC_TOKEN=your_hec_token_here
SPLUNK_HEC_URL=https://192.168.56.1:8088

# MCP server (livehybrid, running locally)
SPLUNK_MCP_URL=http://localhost:8000/sse

# LangSmith — optional but strongly recommended for debugging
LANGSMITH_API_KEY=your_langsmith_key
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=hayyan-ai-soc

# Local paths
CHROMA_PERSIST_DIR=./ai_soc/knowledge/chroma_db
CHECKPOINT_DB=./data/checkpoints.sqlite
```

---

## Required Python Packages (requirements.txt)

```
# LLM + orchestration
langgraph>=0.2.0
langchain>=0.3.0
langchain-google-genai>=2.0.0
langchain-mcp-adapters>=0.1.0
langchain-community>=0.3.0
langchain-core>=0.3.0

# Splunk
splunk-sdk>=2.0.2
mcp>=1.0.0

# Knowledge base
chromadb>=0.5.0
sentence-transformers>=3.0.0

# Observability
langsmith>=0.1.0

# UI + infra
streamlit>=1.40.0
python-dotenv>=1.0.0
pydantic>=2.0.0
httpx>=0.27.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
```

---

## Implementation Roadmap

### Phase 2.0 — Foundation (Week 1) [COMPLETED]
- [x] `git clone https://github.com/livehybrid/splunk-mcp` → (Integrated into core)
- [x] Create project structure: `pyproject.toml`, `requirements.txt`, `.env`
- [x] Write `scripts/test_splunk_connection.py` — confirm connectivity
- [x] Write and unit-test `spl_guardrails.py` — NO LLM needed, pure Python
- [x] Verify Gemini API key works
- [x] Transitioned to ReAct agent architecture (simpler, production-ready)
- [x] Added Groq provider support (free/fast tier)
- [x] Created comprehensive DOCUMENTATION.md

### Phase 2.1 — TriageAgent Standalone (Week 2)
- [ ] Build `TriageAgent` as isolated LangChain agent (no graph yet)
- [ ] Connect to real fired alerts from Splunk REST
- [ ] Verify pydantic output: `TriageVerdict` always valid
- [ ] Measure cost-per-triage with `gemini-2.5-flash`

### Phase 2.2 — Knowledge Base (Week 2)
- [ ] Download `enterprise-attack.json` from `mitre/cti` GitHub
- [ ] Write `build_kb.py` — ingest MITRE into ChromaDB `mitre_attack` collection
- [ ] Write 5 SOC playbooks (one per alert type) in `playbooks/`
- [ ] Ingest playbooks into `soc_playbooks` collection
- [ ] Test RAG: `mitre_attack_rag_search("failed login attempts multiple accounts")`

### Phase 2.3 — LangGraph Assembly (Week 3)
- [ ] Define `SOCState` in `state.py`
- [ ] Build graph: Triage → Investigator → Report (skip Response for now)
- [ ] Add SQLite checkpointer
- [ ] Run end-to-end on a real Password Spray alert
- [ ] Verify investigation follows the 5-step pattern

### Phase 2.4 — Full Pipeline (Week 4)
- [ ] Add `ThreatIntelAgent` + MITRE RAG lookup
- [ ] Add `ResponseAgent` with `interrupt_before=["execute_approved_action"]`
- [ ] Build Streamlit UI: live agent status + Approve/Reject buttons
- [ ] Test HITL: confirm graph hard-stops and waits for approval

### Phase 2.5 — Polish (Week 5)
- [ ] Wire LangSmith tracing
- [ ] Create Splunk HEC token, set up `ai_soc_audit` index
- [ ] Test that every agent action appears in `ai_soc_audit` (AI audits itself)
- [ ] Write README with screenshots of dashboard
- [ ] Demo-ready

---

## Development Commands

```bash
# Activate venv
source .venv/bin/activate        # Linux/Mac
.venv\Scripts\activate           # Windows

# Start Splunk MCP server first (keep running in dedicated terminal)
bash scripts/start_splunk_mcp.sh
# or manually: cd splunk-mcp && poetry run python splunk_mcp.py sse

# Verify everything connects
python scripts/test_splunk_connection.py

# Run agent headless (processes all current fired alerts)
python scripts/run_agent.py

# Run Streamlit dashboard
streamlit run ai_soc/ui/streamlit_app.py

# Rebuild knowledge base (after adding new playbooks or updating MITRE)
python scripts/backfill_kb.py

# Run tests
pytest tests/ -v
pytest tests/test_spl_guardrails.py -v   # run guardrail tests first, no LLM needed
```

---

## Reference Implementation

**Omar Santos — `santosomar/AI-agents-for-cybersecurity` (GitHub)**

This is the primary reference codebase. Study `part5_agents_and_tools/` specifically — it contains:
- Working LangGraph workflows for cybersecurity
- MCP integration examples for security tools
- RAG pipelines for threat intelligence
- Prompt templates for SOC investigation tasks

Omar Santos is a Cisco Distinguished Engineer and co-lead of the DEF CON Red Team Village. His patterns are production-grade. When in doubt about agent design, check his repo first.

---

## Claude Code Working Rules

When writing any code in this project:

1. **Always read `.env` via `config.py`.** Never hardcode any credential, IP, or path anywhere else.

2. **Always call `spl_guardrails.validate()` before any `splunk_search` tool call.** No exceptions. If validation fails, log the reason and stop — do not retry with a modified query without re-validating.

3. **Every agent returns a pydantic model.** No free-form string returns. `TriageAgent` → `TriageVerdict`. `InvestigatorAgent` → `Investigation`. Etc.

4. **Always pass `{"configurable": {"thread_id": alert_id}}` to graph invocations.** This is how LangGraph maintains per-alert state across checkpoints.

5. **The InvestigatorAgent must follow the 5-step pattern** (Understand → Generate SPL → Execute → Analyze → Report Findings) for every investigation. Do not shortcut this.

6. **HITL is sacred.** Never remove `interrupt_before` from `ResponseAgent`. Never add auto-execution logic to response tools.

7. **Evidence citations are required in every report.** Format: `[Index: linux_secure | Time: 2024-01-15 14:23:01 | Event: Failed password for root from 192.168.56.10]`

8. **When Splunk SDK and MCP disagree**, trust the SDK — MCP is a subset of what the SDK can do.

9. **Test with the lab's real data.** The lab has 27,341+ events across 5 indexes. Use them. Don't mock Splunk responses in integration tests.

10. **Keep agents single-purpose.** If a new responsibility appears, create a new agent file. Do not add investigation logic to `TriageAgent` or reporting logic to `InvestigatorAgent`.

---

## Planned Future Additions

- [ ] AbuseIPDB + VirusTotal integration in `ThreatIntelAgent` (needs API keys)
- [ ] Vulnerable web apps on Rocky Linux (command injection, XSS) — more signals for agents
- [ ] CIM field mapping for cleaner cross-index queries
- [ ] Splunk Add-on for Sysmon (auto field extraction — simplifies Sysmon SPL)
- [ ] Join Rocky Linux to `hayyan.local` domain
- [ ] Kerberoasting simulation against `svc_it` SPN
- [ ] Fine-tune Gemini SPL generation prompts using actual lab query history