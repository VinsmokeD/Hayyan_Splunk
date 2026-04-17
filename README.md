# Hayyan SOC — AI Intelligence Platform

Enterprise-grade LangGraph + LangChain multi-agent SOC system connected to Splunk.

## Architecture

```
User (Browser UI)
  └─► FastAPI WebSocket (/ws/chat)
        └─► LangGraph SOC Workflow
              ├─► Triage Node        — classifies intent, routes to specialist
              ├─► Query Specialist   — expert SPL, runs Splunk searches
              ├─► Alert Triage       — fetches & analyzes fired alerts
              ├─► Investigator       — deep-dive threat investigation
              ├─► Report Agent       — IOC + MITRE ATT&CK reports
              └─► Synthesize Node    — final actionable report
                    └─► Splunk REST Client (port 8089)
                          └─► Splunk SIEM
                                ├─► index=windows_events (AD, Sysmon)
                                ├─► index=linux_audit
                                ├─► index=linux_web
                                └─► index=linux_secure
```

## Environment

- **AD Domain**: hayyan.local — DC01 @ 192.168.56.10
- **Rocky Linux**: 192.168.56.20
- **Splunk indexes**: linux_audit, linux_web, linux_secure, windows_events, sysmon
- **Known users**: akhalil, snasser, svc_it, jdoe, jsmith

## Quick Start

### 1. Prerequisites
- Python 3.11+
- Splunk Enterprise running with REST API on port 8089
- Anthropic API key

### 2. Setup
```powershell
cd C:\Users\Mahmo\Hayyan_Splunk
.\setup.ps1
```

### 3. Configure `.env`
```
ANTHROPIC_API_KEY=sk-ant-...
SPLUNK_HOST=<your-splunk-ip>
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=<your-password>
```

### 4. Run
```powershell
.\run.ps1
```

Open **http://localhost:8500** in your browser.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Chat UI |
| `POST` | `/api/chat` | Single-turn chat (returns full report) |
| `WS`   | `/ws/chat` | Streaming multi-turn chat |
| `GET`  | `/api/health` | Health check (Splunk + API status) |
| `GET`  | `/api/alerts` | Live triggered Splunk alerts |
| `GET`  | `/api/indexes` | Splunk index stats |
| `GET`  | `/docs` | FastAPI auto-docs (Swagger) |

## Agent Capabilities

### 🎯 Triage
Auto-routes your request to the right specialist based on intent.

### 🔍 Query Specialist
- Runs expert SPL queries against all indexes
- Enriches results with field stats
- Identifies anomalies and suggests follow-up queries

### 🚨 Alert Triage
- Fetches all currently fired Splunk alerts
- Assigns MITRE ATT&CK tactic/technique
- Recommends immediate containment actions

### 🕵️ Investigator
- Deep-dive threat investigations (IP, user, incident)
- Chains queries to build event timelines
- Maps to MITRE ATT&CK framework
- Concludes with confirmed/suspected/false positive verdict

### 📋 Report Writer
- Executive summary + technical findings
- Full MITRE ATT&CK mapping table
- IOC list (IPs, users, domains, hashes)
- Actionable containment and mitigation steps
- Monitoring SPL queries

## Project Structure

```
Hayyan_Splunk/
├── main.py                    # Entry point (uvicorn)
├── requirements.txt
├── pyproject.toml             # black + mypy config
├── .env                       # Runtime secrets (git-ignored)
├── .env.example               # Template
├── setup.ps1                  # One-time setup
├── run.ps1                    # Start server
└── soc_agents/
    ├── core/
    │   ├── config.py          # Pydantic settings
    │   ├── models.py          # LangGraph SOCState
    │   └── splunk_client.py   # Splunk REST client
    ├── tools/
    │   └── splunk_tools.py    # LangChain @tool definitions
    ├── agents/
    │   └── soc_graph.py       # LangGraph workflow
    ├── api/
    │   └── app.py             # FastAPI + WebSocket
    └── ui/
        └── index.html         # SOC chat interface
```

## Security Notes

- All Splunk communication stays within the local network
- No credentials are logged or exposed in API responses
- WebSocket connections are scoped to a single `thread_id` session
- `.env` is git-ignored — never commit API keys
