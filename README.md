# Hayyan SOC — Autonomous AI Threat Investigator

Enterprise-grade LangGraph + LangChain multi-agent SOC system powered by Google Gemini. Autonomous Tier-1 analyst that watches Splunk, investigates alerts, and generates incident reports.

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
- Python 3.10+
- Splunk Enterprise (Docker or on-prem) with REST API on port 8089
- Google Gemini API Key (free tier works)

### 2. Install & Setup
```bash
# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1

# Mac/Linux bash
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure `.env`
Copy `.env.example` to `.env` and fill in:
```
GOOGLE_API_KEY=your_gemini_api_key_here
SPLUNK_HOST=192.168.56.1
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=Hayyan@2024!
SPLUNK_SCHEME=https
MODEL_NAME=gemini-2.5-flash
```

### 4. Initialize Knowledge Base
```bash
python soc_agents/knowledge/build_kb.py
```

### 5. Run the System
```bash
# Terminal 1: Start API server
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload

# Terminal 2 (optional): Run Streamlit dashboard
streamlit run soc_agents/ui/streamlit_app.py
```

Open **http://localhost:8500** for web UI or **http://localhost:8501** for dashboard.

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
