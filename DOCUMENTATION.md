# Hayyan SOC — Complete Project Documentation

**Version:** 2.0 (Production-Ready)  
**Last Updated:** April 18, 2026  
**Author:** Mahmoud, SOC Intern at Hayyan Horizons  
**Status:** Fully Functional — Groq + Gemini dual-provider support

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Installation Guide](#installation-guide)
5. [Configuration](#configuration)
6. [API Documentation](#api-documentation)
7. [Agent System](#agent-system)
8. [Tools Reference](#tools-reference)
9. [Usage Examples](#usage-examples)
10. [Deployment Guide](#deployment-guide)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)
13. [Development & Contributing](#development--contributing)
14. [Roadmap & Future Work](#roadmap--future-work)

---

## Project Overview

### What is Hayyan SOC?

Hayyan SOC is an **AI-powered Tier-1 security analyst** designed for Hayyan Horizons' home lab environment. It's a FastAPI server that runs a **single ReAct agent** powered by Groq or Google Gemini LLMs, connecting to a Splunk SIEM to investigate alerts, correlate security events, and generate incident reports.

### Key Features

- **🤖 ReAct Agent Architecture** — LLM chooses which tool to call, executes, and iterates until investigation is complete
- **🔍 8 Splunk Tools** — Query any index, investigate IPs/users, fetch alerts, validate SPL queries
- **🛡️ SPL Guardrails** — Blocks destructive commands (`delete`, `drop`, etc.) before execution
- **🚨 Multi-Index Investigation** — Correlates Windows events, Sysmon, Linux auditd, nginx logs, SSH
- **🏷️ MITRE ATT&CK Mapping** — Automatically tags findings with technique IDs (T1110, T1595, T1558, etc.)
- **📊 FastAPI + WebSocket** — REST API for single-turn chat, WebSocket for streaming responses
- **💰 Dual-Provider LLM** — Groq free tier (14,400 req/day) with Gemini fallback
- **🎯 Web UI** — Clean chat interface + live alerts dashboard
- **⚡ Zero Database Dependencies** — No PostgreSQL, Redis, or ChromaDB. Pure Splunk + LLM.

### Use Cases

1. **Automated Alert Triage** — User asks "analyze fired alerts" → agent fetches and summarizes
2. **Threat Investigation** — "Investigate IP 192.168.56.10" → agent chains queries across all indexes
3. **User Activity Timeline** — "What did user jdoe do in the last 24h?" → comprehensive log review
4. **Incident Report Writing** — "Write a report on the password spray" → markdown with timeline, IoCs, recommendations
5. **SPL Query Help** — "Show me failed AD logons by source IP" → agent generates and validates SPL

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│ User (Browser)                                              │
│ http://localhost:8500/                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTP/WebSocket
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ FastAPI Server (port 8500)                                  │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ Endpoints:                                               ││
│ │ GET  /             → HTML Web UI                         ││
│ │ POST /api/chat     → Single-turn chat (blocks until done)││
│ │ WS   /ws/chat      → Streaming chat (live tool output)   ││
│ │ GET  /api/health   → Splunk + API status                 ││
│ │ GET  /api/alerts   → Current fired alerts                ││
│ │ GET  /api/indexes  → Index statistics                    ││
│ └──────────────────────────────────────────────────────────┘│
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ LangGraph ReAct Agent
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ SOC ReAct Agent (soc_graph.py)                              │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ LLM (Groq llama-3.3-70b or Gemini)                       ││
│ │ ┌───────────────────────────────────────────────────────┐││
│ │ │ System Prompt:                                        │││
│ │ │ - Infrastructure map (DC01, Rocky, Splunk)            │││
│ │ │ - Index descriptions + what to find in each           │││
│ │ │ - Tool descriptions (8 Splunk tools)                  │││
│ │ │ - MITRE ATT&CK mapping rules                          │││
│ │ │ - Output format (markdown reports)                    │││
│ │ └───────────────────────────────────────────────────────┘││
│ │ Iterative Loop (ReAct):                                 ││
│ │ 1. LLM reads user request                              ││
│ │ 2. LLM decides which tool to call (or says final answer)││
│ │ 3. Tool executes (Splunk query, alert fetch, etc)       ││
│ │ 4. Result fed back to LLM                               ││
│ │ 5. Loop until investigation complete                    ││
│ └──────────────────────────────────────────────────────────┘│
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTPS/REST (Splunk SDK)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Splunk Enterprise (Docker on host)                          │
│ Port 8089 (REST API)                                        │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ Indexes:                                                 ││
│ │ • windows_events (DC01 AD logs, Kerberos, etc)           ││
│ │ • sysmon (DC01 process/network/file events)              ││
│ │ • linux_audit (Rocky auditd)                             ││
│ │ • linux_web (Rocky nginx access/error)                   ││
│ │ • linux_secure (Rocky SSH/PAM)                           ││
│ │ Total: 27,341+ events                                    ││
│ └──────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Why ReAct (Not Multi-Agent)?

This project uses a **single ReAct agent** instead of multiple specialized agents because:

1. **Simplicity** — Easier to debug, maintain, understand. One system prompt, one LLM, one set of tools.
2. **Sufficient Capability** — Groq's `llama-3.3-70b` is powerful enough for this workload (triage, investigation, reporting).
3. **No Handoff Overhead** — Multi-agent systems need routing logic, state passing, and tool coordination. For a single-user SOC, ReAct's iteration is more cost-effective.
4. **Faster Turnaround** — One LLM call per tool invocation vs. multi-agent message passing.
5. **Better for Interactive Use** — WebSocket streaming shows real-time tool output, which users find more helpful.

### State Management

The agent maintains a **LangGraph SOCState** that persists across tool calls:

```python
class SOCState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]  # Chat history
    investigation_context: dict                           # Findings accumulated
    current_task: str                                     # What agent is doing
    splunk_results: Annotated[list, operator.add]         # Raw query results
    alerts: list                                          # Fired alerts snapshot
    report: str                                           # Final markdown report
    next_agent: str                                       # Routing decision
```

---

## Infrastructure Setup

### Lab Environment Overview

Your physical infrastructure:

| Component | Details |
|---|---|
| **Host OS** | Windows 11 (16GB RAM) |
| **Hypervisor** | VMware Workstation |
| **Network** | VMnet2 host-only: `192.168.56.0/24` |
| **Splunk** | Docker on Windows host |
| **Splunk UI** | `http://localhost:8080` |
| **Splunk REST API** | `https://localhost:8089` |
| **Agent API** | `http://localhost:8500` |

### Virtual Machines

#### Windows Server 2022 (DC01)
- **IP:** `192.168.56.10`
- **Hostname:** `DC01.hayyan.local`
- **Role:** Active Directory Domain Controller
- **Domain:** `hayyan.local`
- **Splunk Forwarder:** Version 10.2.2, sending to `192.168.56.1:9997`
- **Data Collected:**
  - Security event logs (EventCode 4624, 4625, 4720, 4728, 4769, etc.)
  - Sysmon (process creation, network, file activity)
  - System and Application event logs

#### Rocky Linux (Web Server)
- **IP:** `192.168.56.20`
- **NAT IP:** `192.168.229.100` (if testing external connectivity)
- **Splunk Forwarder:** Version 10.2.2
- **Services:** Nginx web server
- **Data Collected:**
  - Nginx access/error logs
  - SSH login attempts (`/var/log/secure`)
  - auditd system call traces (keys: `identity_changes`, `ssh_config_changes`, `command_exec`)

### Splunk Configuration

#### Installed Indexes

```
index=windows_events
  └─ Source: DC01 security event logs
  └─ Notable EventCodes:
     • 4624 — Successful logon
     • 4625 — Failed logon
     • 4720 — User account created
     • 4722 — User account enabled
     • 4728 — User added to group
     • 4768/4769 — Kerberos ticket requested/granted
     • 4672 — Special privileges assigned

index=sysmon
  └─ Source: Sysmon ETW (DC01)
  └─ Notable EventCodes:
     • EventCode 1 — Process creation
     • EventCode 3 — Network connection
     • EventCode 11 — File created
     • EventCode 22 — DNS query

index=linux_web
  └─ Source: Nginx logs (Rocky)
  └─ Fields: clientip, status (404, 200, 500), request, user_agent

index=linux_secure
  └─ Source: SSH/PAM logs (Rocky /var/log/secure)
  └─ Fields: action (Failed password, Accepted), src, user

index=linux_audit
  └─ Source: auditd logs (Rocky)
  └─ Fields: type, key (identity_changes, command_exec)
  └─ Contains: user creation, file modifications, command execution
```

#### Configured Alerts (Scheduled Searches)

| Alert Name | SPL | Schedule | Trigger Condition |
|---|---|---|---|
| **Password Spray Detected** | `index=windows_events EventCode=4625 \| stats count by src_ip` | Every 5 min | count > 5 |
| **Web Scanner Detected** | `index=linux_web status=404 \| stats count by clientip` | Every 5 min | count > 15 per IP |
| **Linux Identity Change** | `index=linux_audit key=identity_changes` | Every 10 min | Any match |

#### Index Statistics

```
Total Events Across All Indexes: 27,341+
├─ windows_events:  ~12,863 events (largest)
├─ sysmon:          ~varies (DC01 Sysmon activity)
├─ linux_audit:     ~varies (auditd syscalls)
├─ linux_web:       ~varies (Nginx requests)
└─ linux_secure:    ~varies (SSH attempts)
```

### Active Directory Structure

```
Domain: hayyan.local
├─ Domain Controller: DC01.hayyan.local (192.168.56.10)
├─ OUs:
│  ├─ SOC_Team
│  └─ Hayyan_Staff
├─ Security Groups:
│  └─ SOC_Admins (high-value targets for investigation)
└─ Known Users:
   ├─ akhalil (SOC analyst)
   ├─ snasser (security staff)
   ├─ svc_it (service account with SPN: HTTP/webserver.hayyan.local) ← Kerberoasting target
   ├─ jdoe
   └─ jsmith
```

---

## Installation Guide

### Prerequisites

- **Python 3.10+** (tested on 3.11, 3.12, 3.14)
- **Splunk Enterprise** running and accessible on port 8089
- **API Key:**
  - Either **Groq API Key** (free: llama-3.3-70b, 14,400 req/day) — recommended
  - Or **Google Gemini API Key** (fallback)
- **Git** (to clone repo)

### Step 1: Clone the Repository

```bash
cd C:\Users\Mahmo
git clone https://github.com/yourusername/Hayyan_Splunk.git
cd Hayyan_Splunk
```

### Step 2: Create Virtual Environment

**Windows PowerShell:**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Mac/Linux bash:**
```bash
python -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**What you get:**
- FastAPI + Uvicorn (web framework)
- LangChain + LangGraph (agent orchestration)
- Groq + Gemini SDKs (LLM providers)
- python-dotenv + pydantic (config management)
- requests (HTTP to Splunk REST API)

### Step 4: Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```bash
# LLM Provider — Choose ONE:

# Option A: Groq (recommended — free 14,400 req/day)
GROQ_API_KEY=gsk_your_groq_api_key_here
MODEL_NAME=llama-3.3-70b-versatile

# Option B: Google Gemini (fallback)
GOOGLE_API_KEY=your_google_api_key_here
MODEL_NAME=gemini-2.5-flash

# Splunk Configuration
SPLUNK_HOST=localhost          # or 192.168.56.1 for Docker
SPLUNK_PORT=8089               # REST API port
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=Hayyan@2024!
SPLUNK_SCHEME=https
SPLUNK_VERIFY_SSL=false        # Lab uses self-signed cert

# API Server
API_HOST=0.0.0.0
API_PORT=8500
```

**Where to get API Keys:**

**Groq:** https://console.groq.com — Sign up free, get instant API key, 14,400 req/day  
**Gemini:** https://aistudio.google.com — Sign up with Google account, get free API key

### Step 5: Verify Installation

Test that Splunk is reachable:

```bash
python -c "from soc_agents.core.splunk_client import SplunkClient; c = SplunkClient(); print('Splunk OK' if c.ping() else 'Splunk unreachable')"
```

Expected output:
```
Splunk OK
```

If you get `Splunk unreachable`, check:
1. Is Splunk running? (`docker ps | grep splunk`)
2. Is port 8089 exposed? (`docker inspect splunk | grep -i 8089`)
3. Is `.env` pointing to the right host?

---

## Configuration

### Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| **GROQ_API_KEY** | (empty) | Groq API key. If set, takes precedence over Gemini. |
| **GOOGLE_API_KEY** | (empty) | Google Gemini API key (fallback if Groq not set). |
| **MODEL_NAME** | llama-3.3-70b-versatile | LLM model to use. See [Model Options](#model-options). |
| **SPLUNK_HOST** | localhost | Splunk hostname or IP |
| **SPLUNK_PORT** | 8089 | Splunk REST API port |
| **SPLUNK_USERNAME** | admin | Splunk admin username |
| **SPLUNK_PASSWORD** | Hayyan@2024! | Splunk admin password |
| **SPLUNK_SCHEME** | https | http or https |
| **SPLUNK_VERIFY_SSL** | false | true/false — set to false for self-signed certs |
| **API_HOST** | 0.0.0.0 | API server bind address |
| **API_PORT** | 8500 | API server port |
| **LANGSMITH_API_KEY** | (empty) | LangSmith tracing (optional, for debugging) |
| **LANGSMITH_TRACING** | false | Enable LangSmith tracing |
| **LANGSMITH_PROJECT** | hayyan-ai-soc | LangSmith project name |
| **CHROMA_PERSIST_DIR** | ./data/chroma_db | ChromaDB vector store path (future) |
| **CHECKPOINT_DB** | ./data/checkpoints.sqlite | SQLite checkpoint db path (future) |

### Model Options

#### Groq Models (Recommended)

```bash
# Most capable — use this
llama-3.3-70b-versatile

# Faster, lighter (alternative)
gemma2-9b-it
mixtral-8x7b-32768
```

**Free Tier Limits:**
- 14,400 requests/day (all models combined)
- No rate limiting per minute (burst-friendly)
- Perfect for SOC lab workload

#### Google Gemini Models

```bash
# Fast, good quality
gemini-2.5-flash

# More capable, slower (use for complex investigations)
gemini-2.5-pro
```

**Free Tier Limits:**
- 2 million tokens/month (not per day!)
- Higher latency than paid tier

### Loading Configuration

The agent loads `.env` via `soc_agents/core/config.py`:

```python
from pathlib import Path
from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

class Settings(BaseSettings):
    groq_api_key: str = ""
    google_api_key: str = ""
    model_name: str = "llama-3.3-70b-versatile"
    splunk_host: str = "localhost"
    # ... rest of settings
    
    class Config:
        env_file = str(_ENV_FILE)
        env_file_encoding = "utf-8"
        case_sensitive = False
```

**Key Behavior:**
- Settings are loaded from `.env` at server startup
- If you change `.env`, you must restart the server
- Windows PowerShell workers may have different CWDs; path is resolved absolutely

---

## API Documentation

### Endpoints Overview

| Method | Path | Response | Description |
|---|---|---|---|
| `GET` | `/` | HTML | Web UI chat interface |
| `POST` | `/api/chat` | JSON | Single-turn investigation (blocking) |
| `WS` | `/ws/chat` | JSON stream | Streaming chat with live tool output |
| `GET` | `/api/health` | JSON | Splunk + API health status |
| `GET` | `/api/alerts` | JSON | Currently triggered Splunk alerts |
| `GET` | `/api/indexes` | JSON | Index statistics and event counts |
| `GET` | `/docs` | HTML | Swagger API documentation |

### GET `/`

**Serve Web UI**

Returns the HTML chat interface. Try it first to ensure server is running.

```bash
curl http://localhost:8500/
# Returns: <html>...</html>
```

---

### GET `/api/health`

**Check Splunk + API Status**

```bash
curl http://localhost:8500/api/health | jq
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "splunk": "connected via https://localhost:8089",
  "model": "llama-3.3-70b-versatile"
}
```

**Response (if Splunk unreachable, 503):**
```json
{
  "status": "error",
  "splunk": "unreachable at localhost:8089"
}
```

---

### GET `/api/alerts`

**Fetch Currently Triggered Alerts**

```bash
curl http://localhost:8500/api/alerts | jq
```

**Response (200 OK):**
```json
{
  "alerts": [
    {
      "name": "Password Spray Detected",
      "trigger_time": "2026-04-18 14:23:45",
      "severity": "high",
      "trigger_count": 7
    },
    {
      "name": "Web Scanner Detected",
      "trigger_time": "2026-04-18 14:24:10",
      "severity": "medium",
      "trigger_count": 1
    }
  ]
}
```

**Response (if Splunk unreachable, 503):**
```json
{
  "error": "Splunk unreachable: ConnectionError",
  "alerts": []
}
```

---

### GET `/api/indexes`

**Fetch Index Statistics**

```bash
curl http://localhost:8500/api/indexes | jq
```

**Response (200 OK):**
```json
{
  "indexes": [
    {
      "name": "windows_events",
      "total_event_count": 12863,
      "size_mb": 145.2,
      "earliest_time": "2026-04-17 10:00:00",
      "latest_time": "2026-04-18 14:30:00"
    },
    {
      "name": "sysmon",
      "total_event_count": 4521,
      "size_mb": 67.8,
      "earliest_time": "2026-04-17 10:00:00",
      "latest_time": "2026-04-18 14:30:00"
    },
    {
      "name": "linux_audit",
      "total_event_count": 6234,
      "size_mb": 89.3,
      "earliest_time": "2026-04-17 10:00:00",
      "latest_time": "2026-04-18 14:30:00"
    },
    {
      "name": "linux_web",
      "total_event_count": 2145,
      "size_mb": 23.4,
      "earliest_time": "2026-04-17 10:00:00",
      "latest_time": "2026-04-18 14:30:00"
    },
    {
      "name": "linux_secure",
      "total_event_count": 1578,
      "size_mb": 15.7,
      "earliest_time": "2026-04-17 10:00:00",
      "latest_time": "2026-04-18 14:30:00"
    }
  ]
}
```

---

### POST `/api/chat`

**Single-Turn Conversation (Blocking)**

Sends a message, waits for agent to complete investigation, returns full report.

**Request:**
```bash
curl -X POST http://localhost:8500/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Analyze the password spray alert",
    "thread_id": "optional-session-id"
  }' | jq
```

**Parameters:**
- `message` (string, required) — User's question or request
- `thread_id` (string, optional) — Session ID for multi-turn continuity. If omitted, new UUID is generated.

**Response (200 OK):**
```json
{
  "thread_id": "abc123def456",
  "report": "## Summary\nPassword spray detected on DC01 from 192.168.56.20...\n\n## Timeline\n| Time | Event | Source |\n|---|---|---|\n| 2026-04-18 14:23:10 | 12 failed logons (EventCode 4625) | windows_events |\n...\n\n## MITRE ATT&CK Mapping\n- T1110.003 — Password Spraying\n\n## Recommended Actions\n1. Disable the attacking account or block the IP\n2. Review recent successful logons from this IP\n"
}
```

**Response (429 Rate Limited):**
```json
{
  "error": "Gemini rate limit hit. Wait ~60s or switch MODEL_NAME to gemini-2.0-flash in .env."
}
```

**Response (500 Error):**
```json
{
  "error": "Connection refused: Splunk unreachable"
}
```

---

### WebSocket `/ws/chat`

**Streaming Conversation**

Opens a persistent WebSocket connection. Send messages, receive live tool output and final report.

**JavaScript Example:**
```javascript
const ws = new WebSocket("ws://localhost:8500/ws/chat");

ws.onopen = () => {
  ws.send(JSON.stringify({
    message: "Investigate IP 192.168.56.20",
    thread_id: "session-123"
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.type, data.content);
  // type: "tool_input" — agent decided to call a tool
  // type: "tool_output" — tool result (Splunk query results, etc)
  // type: "agent_output" — agent's interpretation
  // type: "final" — final report
};

ws.onerror = (error) => {
  console.error("WebSocket error:", error);
};
```

**Message Stream Example:**

User sends:
```json
{ "message": "What happened with user jdoe?", "thread_id": "s1" }
```

Server sends back (in order):
```json
{ "type": "tool_input", "content": "Calling investigate_user with username=jdoe" }
{ "type": "tool_output", "content": "{\"logon_events\": [{\"_time\": \"2026-04-18 10:23:45\", \"EventCode\": 4625, \"count\": 3}]}" }
{ "type": "agent_output", "content": "User jdoe had 3 failed logon attempts. Checking for privilege escalation..." }
{ "type": "tool_input", "content": "Calling run_splunk_query with spl='index=windows_events TargetUserName=jdoe EventCode IN (4672, 4673, 4674)'" }
{ "type": "tool_output", "content": "{\"results\": []}" }
{ "type": "agent_output", "content": "No privilege escalation detected. User activity appears normal except for login failures." }
{ "type": "final", "content": "## User Investigation: jdoe\n..." }
```

---

## Agent System

### Overview

The agent is a **LangGraph ReAct Agent** built on top of Google's Gemini or Groq's Llama. It uses the standard Reason+Act pattern:

1. **Reason** — LLM reads the user message and decides which tool(s) to call
2. **Act** — Execute the tool (Splunk query, alert fetch, etc.)
3. **Reflect** — Feed results back to LLM for next iteration
4. **Loop** until investigation is complete

### System Prompt

The agent's behavior is controlled by a detailed system prompt in `soc_agents/agents/soc_graph.py`:

```
You are the Hayyan SOC AI Analyst — a Tier-1 security analyst assistant for Hayyan Horizons.

## Environment You Monitor

**Infrastructure**
- Windows Server 2022 Domain Controller: DC01.hayyan.local @ 192.168.56.10
- Rocky Linux web server: 192.168.56.20
- Splunk Enterprise: Docker on host @ 192.168.56.1:8089
- Active Directory domain: hayyan.local
- Known AD users: akhalil, snasser, svc_it, jdoe, jsmith

**Splunk Indexes & What They Contain**
[Table of 5 indexes and their data types]

**Configured Alerts**
[Password Spray, Web Scanner, Linux Identity Change]

## How You Work

1. Understand the request. Parse what the user is asking.
2. Pick the right tool. You have 8 Splunk tools available.
3. Always validate before querying.
4. Chain tools when needed.
5. Interpret the data.
6. Map to MITRE ATT&CK.
7. Recommend containment.

## Output Format

For quick questions, give a short direct answer + the tool data you used.

For investigations, produce a structured markdown report with:
- Summary
- Timeline
- Findings
- MITRE ATT&CK Mapping
- IoCs
- Recommended Actions
- Monitoring SPL

## Rules

- Never hallucinate data. If you didn't run a tool, don't claim a result.
- If a query returns 0 results, try widening the time range.
- If Splunk is unreachable, say so clearly and stop.
- Be concise.
- When you're done investigating, produce the final report and stop calling tools.
```

### Building the Agent

The agent is built and cached at module import time:

```python
# soc_agents/agents/soc_graph.py

def _build_llm():
    cfg = get_settings()
    if cfg.groq_api_key:
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=cfg.model_name,
            groq_api_key=cfg.groq_api_key,
            temperature=0,
            max_tokens=4096,
        )
    # Fall back to Gemini
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(
        model=cfg.model_name,
        google_api_key=cfg.google_api_key,
        temperature=0,
        max_output_tokens=4096,
    )

def build_soc_agent():
    """Build the SOC ReAct agent with checkpointing."""
    llm = _build_llm()
    checkpointer = MemorySaver()
    agent = create_react_agent(
        model=llm,
        tools=ALL_SPLUNK_TOOLS,
        prompt=SOC_SYSTEM_PROMPT,
        checkpointer=checkpointer,
    )
    return agent

# Module-level singleton
soc_graph = build_soc_agent()
```

### Invoking the Agent

```python
from soc_agents.agents.soc_graph import soc_graph
from langchain_core.messages import HumanMessage

# Single-turn invocation
thread_id = "session-123"
config = {"configurable": {"thread_id": thread_id}}
state = {"messages": [HumanMessage(content="Analyze the fired alerts")]}

result = soc_graph.invoke(state, config=config)
# result["messages"][-1] contains final answer
```

### Tool Availability

The agent has access to 8 tools:

1. **`check_splunk_health`** — Verify Splunk is reachable
2. **`validate_spl_query`** — Validate SPL before execution
3. **`run_splunk_query`** — Execute any SPL query
4. **`get_triggered_alerts`** — Fetch fired alerts
5. **`get_index_stats`** — Show index event counts
6. **`get_saved_searches`** — List configured alerts
7. **`investigate_ip`** — Deep-dive an IP across all indexes
8. **`investigate_user`** — Deep-dive an AD user

---

## Tools Reference

### check_splunk_health()

**Check Splunk connectivity and health.**

```python
tool.invoke({})
```

**Returns:**
```json
{
  "status": "healthy",
  "reachable": true,
  "total_events_across_indexes": 27341,
  "indexes": ["windows_events", "sysmon", "linux_audit", "linux_web", "linux_secure"]
}
```

---

### validate_spl_query(spl: str) -> dict

**Validate an SPL query for safety BEFORE running it.**

Checks for:
- Blocked commands: `delete`, `drop`, `outputlookup`, `collect`, `sendemail`, `sendalert`, `restart`, `script`
- Time range bounds (max 7 days)
- Subsearch result limits (max 50,000)

```python
tool.invoke({"spl": "index=windows_events EventCode=4625 | stats count by src_ip"})
```

**Response (valid):**
```json
{
  "valid": true,
  "message": "Query is safe to execute"
}
```

**Response (blocked):**
```json
{
  "valid": false,
  "message": "Blocked command detected: delete"
}
```

---

### run_splunk_query(spl: str, earliest: str = "-24h", latest: str = "now", max_results: int = 50) -> str

**Execute a Splunk SPL query and return results.**

```python
tool.invoke({
  "spl": "index=windows_events EventCode=4625 | stats count by src_ip",
  "earliest": "-1h",
  "latest": "now",
  "max_results": 50
})
```

**Returns (JSON string):**
```json
[
  {
    "src_ip": "192.168.56.10",
    "count": "3"
  },
  {
    "src_ip": "192.168.56.20",
    "count": "5"
  }
]
```

---

### get_triggered_alerts() -> str

**Fetch all currently fired Splunk alerts.**

```python
tool.invoke({})
```

**Returns:**
```json
[
  {
    "name": "Password Spray Detected",
    "trigger_time": "2026-04-18 14:23:45",
    "severity": "high",
    "count": 7
  },
  {
    "name": "Web Scanner Detected",
    "trigger_time": "2026-04-18 14:24:10",
    "severity": "medium",
    "count": 1
  }
]
```

---

### get_index_stats() -> str

**Show statistics for all Splunk indexes.**

```python
tool.invoke({})
```

**Returns:**
```json
[
  {
    "name": "windows_events",
    "total_event_count": "12863",
    "size_mb": "145.2",
    "earliest_time": "2026-04-17 10:00:00",
    "latest_time": "2026-04-18 14:30:00"
  },
  {
    "name": "sysmon",
    "total_event_count": "4521",
    "size_mb": "67.8",
    "earliest_time": "2026-04-17 10:00:00",
    "latest_time": "2026-04-18 14:30:00"
  }
]
```

---

### get_saved_searches() -> str

**List all saved searches and scheduled alerts.**

```python
tool.invoke({})
```

**Returns:**
```json
[
  {
    "name": "Password Spray Detected",
    "spl": "index=windows_events EventCode=4625 | stats count by src_ip",
    "cron_schedule": "*/5 * * * *",
    "alert_type": "Add to Triggered Alerts",
    "enabled": true
  }
]
```

---

### investigate_ip(ip_address: str, time_range: str = "-24h") -> str

**Deep-dive investigation of an IP across all indexes.**

```python
tool.invoke({
  "ip_address": "192.168.56.20",
  "time_range": "-24h"
})
```

**Runs 5 targeted queries:**
1. Windows logon failures from IP
2. Windows successful logons from IP
3. Web requests from IP
4. SSH attempts from IP
5. Sysmon network connections to/from IP

**Returns:**
```json
{
  "windows_logon_failures": [
    {
      "Account_Name": "jdoe",
      "EventCode": "4625",
      "count": "3"
    }
  ],
  "windows_successful_logons": [],
  "web_requests": [
    {
      "status": "404",
      "request": "/admin",
      "count": "12"
    }
  ],
  "ssh_attempts": [
    {
      "action": "Failed password",
      "count": "15"
    }
  ],
  "sysmon_network": []
}
```

---

### investigate_user(username: str, time_range: str = "-24h") -> str

**Deep-dive investigation of an AD user across all indexes.**

```python
tool.invoke({
  "username": "jdoe",
  "time_range": "-24h"
})
```

**Runs 5 targeted queries:**
1. All logon events (4624, 4625, 4634, 4648)
2. Privilege usage (4672, 4673, 4674)
3. AD changes (4720, 4722, 4723, 4724, 4725, 4726, 4728)
4. Process creation events
5. Kerberos events (4768, 4769, 4770)

**Returns:**
```json
{
  "logon_events": [
    {
      "EventCode": "4625",
      "IpAddress": "192.168.56.20",
      "count": "5"
    }
  ],
  "privilege_use": [],
  "ad_changes_by_user": [
    {
      "_time": "2026-04-18 14:23:10",
      "EventCode": "4720",
      "TargetUserName": "newuser"
    }
  ],
  "process_creation": [
    {
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "CommandLine": "cmd.exe /c whoami",
      "count": "2"
    }
  ],
  "kerberos": []
}
```

---

## Usage Examples

### Example 1: Analyze Fired Alerts

**Request:**
```bash
curl -X POST http://localhost:8500/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What alerts have fired in the last hour?"}'
```

**Agent Steps:**
1. Calls `get_triggered_alerts()` → sees Password Spray + Web Scanner alerts
2. For each alert, calls `run_splunk_query()` to get details
3. Interprets results and generates markdown report

**Sample Response:**
```markdown
## Alert Summary

**Currently Triggered Alerts (2 active):**

### 1. Password Spray Detected
- **Trigger Time:** 2026-04-18 14:23:45
- **Severity:** High
- **Trigger Count:** 7
- **Finding:** 47 failed login attempts (EventCode 4625) from IP 192.168.56.20 to user accounts on DC01
- **Notable Accounts:** jdoe (15 failures), jsmith (12 failures), akhalil (8 failures)
- **MITRE Mapping:** T1110.003 — Password Spraying

### 2. Web Scanner Detected
- **Trigger Time:** 2026-04-18 14:24:10
- **Severity:** Medium
- **Trigger Count:** 1
- **Finding:** 67 HTTP 404 errors from IP 192.168.56.20 to Nginx on Rocky
- **MITRE Mapping:** T1595.002 — Active Scanning / Vulnerability Scanning

## Recommended Actions
1. Block IP 192.168.56.20 at firewall
2. Review audit logs on DC01 for any successful logons from this IP in the last 24h
3. Check Nginx logs for any successful requests from this IP
```

---

### Example 2: Investigate an IP

**Request:**
```bash
curl -X POST http://localhost:8500/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Investigate 192.168.56.20 — what is it doing?"}'
```

**Agent Steps:**
1. Calls `investigate_ip("192.168.56.20", "-24h")`
2. Parses 5 subcategory results
3. Chains additional queries if interesting patterns found
4. Produces comprehensive report

**Sample Response:**
```markdown
## Investigation: IP 192.168.56.20

### Executive Summary
IP 192.168.56.20 (Rocky Linux web server) shows mixed legitimate and suspicious activity:
- **Legitimate:** Normal internal web server operation (nginx)
- **Suspicious:** 47 failed AD logon attempts, 67 HTTP 404 scanning requests

### Timeline

| Time (UTC) | Event | Source | Details |
|---|---|---|---|
| 2026-04-18 14:20:10 | Failed logon (jdoe) | windows_events (4625) | 12 attempts, 3-second intervals |
| 2026-04-18 14:20:45 | Failed logon (jsmith) | windows_events (4625) | 8 attempts |
| 2026-04-18 14:21:30 | 404 errors spike | linux_web | 67 requests to /admin, /config, /backup paths |
| 2026-04-18 14:22:15 | SSH failures | linux_secure | 15 "Failed password" for root |

### Affected Assets
- **Primary:** Rocky Linux server (192.168.56.20)
- **Secondary:** DC01.hayyan.local (attempted logons)

### Indicators of Compromise
- **IP:** 192.168.56.20 (internal — this is Rocky itself, so behavior is expected if Rocky is compromised)
- **Techniques:** Password spray, web vulnerability scanning, SSH brute force
- **Pattern:** Coordinated, systematic attacks within same 2-minute window

### MITRE ATT&CK Mapping
| Tactic | Technique | ID | Confidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Medium |
| Credential Access | Brute Force: Password Spraying | T1110.003 | High |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Medium |
| Reconnaissance | Active Scanning | T1595.002 | High |

### Recommendations
1. **IMMEDIATE:** Block SSH access to DC01 from 192.168.56.20 if this isn't the local admin
2. Isolate Rocky Linux from network (or restart it to clear compromise)
3. Rotate AD passwords for jdoe, jsmith, akhalil
4. Review nginx access logs for successful exploitation attempts
5. Check if Rocky was recently compromised (review process execution events if available)

### Monitoring SPL
```spl
# Monitor future password spray from this IP
index=windows_events EventCode=4625 src_ip=192.168.56.20 | stats count, latest(_time) by TargetUserName

# Monitor future web scanner activity
index=linux_web clientip=192.168.56.20 status=404 | stats count by request_path
```
```

---

### Example 3: User Investigation

**Request:**
```bash
curl -X POST http://localhost:8500/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What did user svc_it do in the last 48 hours?"}'
```

**Agent Steps:**
1. Calls `investigate_user("svc_it", "-48h")`
2. Examines logon events, privilege escalation, AD changes, process creation
3. Summarizes activity and flags any anomalies

**Sample Response:**
```markdown
## User Investigation: svc_it

**User Profile:**
- Account Name: svc_it
- Type: Service account (HTTP/webserver.hayyan.local SPN)
- Group Memberships: DOMAIN\Domain Users

### Timeline (Last 48 Hours)

| Time | Event | Type | Details |
|---|---|---|---|
| 2026-04-16 10:23:00 | Logon (successful) | 4624 | From 192.168.56.1 (localhost — DC) |
| 2026-04-16 10:24:15 | Kerberos TGS-REQ | 4769 | Request for HTTP/webserver.hayyan.local (self) |
| 2026-04-16 10:25:30 | Process: iisreset.exe | Sysmon 1 | CommandLine: iisreset.exe |
| 2026-04-17 23:45:00 | Logoff | 4634 | Expected logout |
| 2026-04-18 08:00:00 | Logon (successful) | 4624 | From 192.168.56.1 — normal scheduled task |

### Findings
✓ **Normal Pattern:** Service account showing expected behavior
✓ **No Privilege Escalation:** No 4672/4673/4674 events
✓ **No Account Changes:** No 4720/4722/4726 events by this account
✓ **Kerberoasting Risk:** SPN (HTTP/webserver.hayyan.local) is a known target. Consider using managed service accounts (gMSA) or longer password rotation.

### Recommendations
1. Continue monitoring for Kerberoasting attacks against this SPN
2. Ensure svc_it password is rotated quarterly
3. Limit logon hours to business times if possible

### MITRE ATT&CK Mapping
| Technique | ID | Status |
|---|---|---|
| Kerberoasting (potential target) | T1558.003 | Observed (not exploited) |
```

---

## Deployment Guide

### Running Locally (Development)

**Terminal 1 — Start the API server:**

```bash
# Activate venv
.venv\Scripts\Activate.ps1

# Start uvicorn
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload
```

Output:
```
INFO:     Uvicorn running on http://0.0.0.0:8500
INFO:     Application startup complete
```

**Terminal 2 — Use the web UI:**

Open `http://localhost:8500` in a browser. You'll see the chat interface.

**Terminal 3 — Test the API:**

```bash
curl http://localhost:8500/api/health | jq
curl http://localhost:8500/api/alerts | jq
curl -X POST http://localhost:8500/api/chat -d '{"message":"What alerts fired?"}' | jq
```

---

### Running with Uvicorn (Production-Like)

```bash
# Without auto-reload (faster)
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --workers 4
```

**Key Options:**
- `--host 0.0.0.0` — Listen on all interfaces
- `--port 8500` — Default port
- `--workers 4` — 4 worker processes (handles concurrent requests)
- `--log-level info` — Set logging verbosity

---

### Running Behind a Reverse Proxy (Nginx)

Create `/etc/nginx/sites-available/soc-agent`:

```nginx
upstream soc_backend {
    server 127.0.0.1:8500;
}

server {
    listen 80;
    server_name soc.hayyan.local;

    location / {
        proxy_pass http://soc_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
```

Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/soc-agent /etc/nginx/sites-enabled/
sudo nginx -s reload
```

Now access via `http://soc.hayyan.local`

---

### Docker Deployment (Recommended for Production)

Create `Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY soc_agents/ soc_agents/
COPY main.py .
COPY .env .

# Expose port
EXPOSE 8500

# Run server
CMD ["python", "-m", "uvicorn", "soc_agents.api.app:app", "--host", "0.0.0.0", "--port", "8500"]
```

Build and run:
```bash
docker build -t hayyan-soc:latest .

docker run -d \
  --name hayyan-soc \
  -p 8500:8500 \
  -e GROQ_API_KEY=$GROQ_API_KEY \
  -e SPLUNK_HOST=192.168.56.1 \
  -e SPLUNK_PORT=8089 \
  hayyan-soc:latest
```

Check logs:
```bash
docker logs -f hayyan-soc
```

---

## Troubleshooting

### Issue: `Splunk unreachable at localhost:8089`

**Cause:** Splunk is not running or port 8089 is not exposed.

**Fix:**
1. Check if Splunk container is running:
   ```bash
   docker ps | grep splunk
   ```

2. If not running, start it:
   ```bash
   docker run -d --name splunk \
     -p 8080:8000 -p 8088:8088 -p 8089:8089 \
     -e SPLUNK_PASSWORD=Hayyan@2024! \
     splunk/splunk:latest start
   ```

3. If running, verify port exposure:
   ```bash
   docker port splunk | grep 8089
   # Should output: 8089/tcp -> 0.0.0.0:8089
   ```

4. Update `.env` to use the correct host:
   ```bash
   SPLUNK_HOST=192.168.56.1  # or localhost if on same machine
   SPLUNK_PORT=8089
   ```

---

### Issue: `GOOGLE_API_KEY is invalid` or Groq API key not found

**Cause:** .env file is not being loaded or API key is missing.

**Fix:**
1. Verify `.env` exists in project root:
   ```bash
   ls -la .env
   ```

2. Verify the key is set:
   ```bash
   grep -i "GOOGLE_API_KEY" .env
   grep -i "GROQ_API_KEY" .env
   ```

3. If running in Docker, pass the key as env var:
   ```bash
   docker run -e GROQ_API_KEY=gsk_YOUR_KEY hayyan-soc
   ```

4. Restart the server:
   ```bash
   # Kill existing process
   pkill -f uvicorn
   
   # Restart
   python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500
   ```

---

### Issue: `ImportError: No module named 'langchain_groq'`

**Cause:** Dependencies not installed.

**Fix:**
```bash
# Ensure venv is activated
.venv\Scripts\Activate.ps1

# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall
```

---

### Issue: Splunk queries return 0 results

**Cause:** Index doesn't contain data for the time range or field names are wrong.

**Fix:**
1. Check what's in the indexes:
   ```bash
   curl http://localhost:8500/api/indexes | jq
   ```

2. If an index has 0 events, ensure Splunk is receiving data from forwarders:
   - Check Splunk UI: Settings → Data Inputs → Forwarded Data
   - Check that universal forwarders are sending data
   - On Rocky Linux: `sudo service SplunkForwarder status`
   - On DC01: Services app → "SplunkUniversalForwarder" status

3. Ask the agent to investigate with a wider time range:
   ```bash
   curl -X POST http://localhost:8500/api/chat \
     -d '{"message":"Search for EventCode=4625 in the last 7 days"}'
   ```

---

### Issue: Agent hangs or takes >2 minutes

**Cause:** Large Splunk query, network latency, or LLM rate limiting.

**Fix:**
1. Check Groq/Gemini rate limits:
   - Groq: 14,400 req/day (usually plenty)
   - Gemini: 2 million tokens/month

2. If getting 429 (rate limited), wait 60s or switch to a different model:
   ```bash
   # In .env
   MODEL_NAME=gemini-2.0-flash
   ```

3. Check Splunk query performance:
   ```bash
   # In Splunk UI, go to Activity → Job Inspector
   # Look for queries taking >30 seconds and optimize them
   ```

---

### Issue: WebSocket connection closes immediately

**Cause:** CORS misconfiguration or network issue.

**Fix:**
1. Check CORS is enabled in `soc_agents/api/app.py`:
   ```python
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["*"],
       allow_methods=["*"],
       allow_headers=["*"],
   )
   ```

2. Test WebSocket directly:
   ```bash
   # Using wscat
   npm install -g wscat
   wscat -c ws://localhost:8500/ws/chat
   ```

3. Send a test message:
   ```
   > {"message":"Test"}
   < {"type":"tool_input",...}
   ```

---

## Security Considerations

### API Keys

- **Never commit `.env` to Git.** `.gitignore` should include `.env`
- **Use strong passwords.** Splunk admin password should be 16+ characters
- **Rotate keys regularly.** Groq/Gemini API keys should be rotated quarterly
- **Limit key permissions.** If using IAM, restrict API key to necessary Splunk/Gemini APIs only

### Splunk Configuration

- **Require HTTPS.** Splunk REST API uses HTTPS — verify in production
- **Self-signed certs.** Lab uses self-signed certs (SPLUNK_VERIFY_SSL=false). In production, use valid certs.
- **Restrict API access.** Use Splunk roles to limit what the agent can query
- **Audit agent actions.** Log all agent queries to a dedicated index for forensics

### Network Security

- **Lab network is isolated.** 192.168.56.0/24 is host-only, not routable to Internet
- **Rocky Linux has firewall.** Firewalld is enabled with "drop" zone — blocks unsolicited inbound
- **DC01 is isolated.** No NAT access to Internet
- **Agent API can be behind proxy.** Nginx reverse proxy recommended for production

### SPL Guardrails

The agent cannot execute:
- `| delete` — Can't delete data
- `| drop` — Can't drop fields
- `| outputlookup` — Can't write lookups
- `| collect` — Can't forward to another Splunk
- `| sendemail` / `| sendalert` — Can't send messages
- `restart` — Can't restart Splunk
- `| script` — Can't run scripts

**Query time range limits:**
- Max 7 days per query (prevents resource exhaustion)
- Subsearch results capped at 50,000

---

## Development & Contributing

### Project Structure

```
Hayyan_Splunk/
├── main.py                           # Entry point (for CLI if needed)
├── requirements.txt                  # Python dependencies
├── pyproject.toml                    # Black + mypy config
├── .env.example                      # Template (commit this)
├── .env                              # Secrets (git-ignored)
├── README.md                         # Quick start
├── DOCUMENTATION.md                  # This file
├── CLAUDE.md                         # Architecture notes (internal)
│
├── soc_agents/
│   ├── __init__.py
│   │
│   ├── core/                         # Configuration + clients
│   │   ├── config.py                 # Settings loader
│   │   ├── models.py                 # SOCState TypedDict
│   │   └── splunk_client.py          # Splunk REST wrapper
│   │
│   ├── tools/                        # LangChain @tool definitions
│   │   ├── splunk_tools.py           # 8 Splunk tools
│   │   ├── spl_guardrails.py         # Validation + safety checks
│   │   └── __init__.py
│   │
│   ├── agents/                       # LangGraph nodes
│   │   ├── soc_graph.py              # ReAct agent builder
│   │   └── __init__.py
│   │
│   ├── api/                          # FastAPI server
│   │   ├── app.py                    # Endpoints + WebSocket
│   │   └── __init__.py
│   │
│   └── ui/                           # Web UI
│       ├── index.html                # Chat interface
│       └── __init__.py
│
├── data/                             # Runtime data (git-ignored)
│   ├── chroma_db/                    # Future: vector store
│   └── checkpoints.sqlite            # Future: LangGraph state
│
└── tests/                            # Unit tests (future)
    ├── test_spl_guardrails.py
    ├── test_splunk_client.py
    └── __init__.py
```

### Code Style

This project uses **Black** for formatting and **mypy** for type checking.

Format code:
```bash
pip install black mypy
black soc_agents/ tests/
```

Type check:
```bash
mypy soc_agents/
```

Config (in `pyproject.toml`):
```toml
[tool.black]
line-length = 88
target-version = ['py310', 'py311']

[tool.mypy]
python_version = "3.10"
warn_unused_ignores = true
disallow_untyped_defs = false
```

---

### Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

Test a specific file:
```bash
pytest tests/test_spl_guardrails.py -v
```

---

### Adding a New Tool

To add a new tool (e.g., `check_ip_reputation`):

1. **Define the tool** in `soc_agents/tools/splunk_tools.py`:
   ```python
   @tool
   def check_ip_reputation(ip: str) -> str:
       """Check IP reputation against local threat intel lists.
       
       Args:
           ip: IP address to check
       
       Returns:
           Reputation assessment (clean, suspicious, blocked)
       """
       # Implementation
       return json.dumps(result)
   ```

2. **Add to ALL_SPLUNK_TOOLS**:
   ```python
   ALL_SPLUNK_TOOLS = [
       # ... existing tools
       check_ip_reputation,
   ]
   ```

3. **Test it**:
   ```bash
   python -c "from soc_agents.tools.splunk_tools import check_ip_reputation; print(check_ip_reputation.invoke({'ip': '8.8.8.8'}))"
   ```

4. **Update system prompt** in `soc_graph.py` to mention the new tool

---

### Modifying the System Prompt

The system prompt lives in `soc_agents/agents/soc_graph.py`:

```python
SOC_SYSTEM_PROMPT = """You are the Hayyan SOC AI Analyst...

## How You Work
1. ...
2. ...
```

To modify:
1. Edit the string
2. Restart the server
3. Test with a query

Example: To tell the agent to be more aggressive in recommending containment actions:

```python
## Recommendations

IMPORTANT: When investigating potential threats, ALWAYS recommend:
- Disabling the attacking account (if it's not a high-value user)
- Blocking the source IP at firewall
- Resetting passwords for affected users

Be specific with each recommendation.
```

---

### Changing the LLM Model

To use a different model:

1. **Set the model in `.env`:**
   ```bash
   MODEL_NAME=gemini-2.0-flash
   ```

2. **Or use code:**
   ```python
   from soc_agents.core.config import get_settings
   settings = get_settings()
   print(settings.model_name)  # See current model
   ```

3. **Restart server:**
   ```bash
   pkill -f uvicorn
   python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500
   ```

---

## Roadmap & Future Work

### Phase 2.1 — Knowledge Base (ChromaDB)

- [ ] Ingest MITRE ATT&CK (from `enterprise-attack.json`)
- [ ] RAG search for techniques during investigation
- [ ] Ingest SOC playbooks (5 per alert type)
- [ ] Embed past incident reports for similarity search

**Impact:** Better MITRE mapping, smarter alert triage, playbook-driven investigation

---

### Phase 2.2 — Multi-Agent Graph (LangGraph)

- [ ] Replace ReAct with specialized agents:
  - `TriageAgent` — Fast alert classification
  - `InvestigatorAgent` — Deep-dive 5-step investigation
  - `ReportAgent` — Synthesis + MITRE mapping
  - `ResponseAgent` — HITL-gated response actions
- [ ] Add Supervisor node for routing
- [ ] Implement graph state persistence (SQLite)

**Impact:** Parallel investigation, better cost control, human-in-the-loop for actions

---

### Phase 2.3 — Streamlit Dashboard

- [ ] Real-time alert ticker
- [ ] Live agent status (which tool running, what query)
- [ ] Approve/reject response actions
- [ ] Investigation history + drill-down

**Impact:** Better visibility, human oversight, audit trail

---

### Phase 2.4 — LangSmith Integration

- [ ] Wire LangSmith API for observability
- [ ] Trace every agent step, tool call, LLM decision
- [ ] Debug failures (why did agent pick wrong tool?)
- [ ] Cost monitoring (tokens/day, cost/alert)

**Impact:** Production-grade debugging, cost optimization

---

### Phase 2.5 — Splunk HEC Audit Trail

- [ ] Create `ai_soc_audit` index
- [ ] Log every agent action to Splunk
- [ ] Every tool call with inputs + outputs
- [ ] Every agent decision + reasoning

**Impact:** AI audits itself, full forensic trail, compliance

---

### Future Enhancements

- [ ] **AbuseIPDB integration** — Real-time IP reputation (T1595 indicator)
- [ ] **VirusTotal integration** — File hash + domain reputation
- [ ] **Slack/Teams integration** — Send alerts to SOC team
- [ ] **Auto-response playbooks** — Disable user, block IP, quarantine host (gated by approval)
- [ ] **Automated evidence collection** — Grab memory dumps, event logs for forensics
- [ ] **CIM field mapping** — Normalize across all sources
- [ ] **Model fine-tuning** — Use real lab query history to fine-tune Gemini/Llama

---

## Support & Contact

For issues, questions, or contributions:

- **GitHub Issues:** https://github.com/yourusername/Hayyan_Splunk/issues
- **Email:** mahmoudmallabadis@gmail.com
- **Splunk Slack:** @mahmoud in Splunk Community

---

## References

### Key Technologies

- **LangGraph** — https://langgraph.js.org/ (agent orchestration)
- **LangChain** — https://langchain.com/ (tool binding, prompts)
- **Groq** — https://groq.com/ (LLM provider, free 14,400 req/day)
- **Google Gemini** — https://ai.google.dev/ (LLM provider, fallback)
- **Splunk REST API** — https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog
- **MITRE ATT&CK** — https://attack.mitre.org/ (technique mapping)

### Reference Implementations

- **Omar Santos** — `santosomar/AI-agents-for-cybersecurity` (GitHub) — Production LangGraph + MCP patterns for SOC

---

## License

[Your License Here — MIT, Apache 2.0, etc.]

---

**Documentation Generated:** April 18, 2026  
**Last Tested:** Phase 2.0 Production-Ready (Groq + Gemini dual support)  
**Status:** Fully Functional ✅
