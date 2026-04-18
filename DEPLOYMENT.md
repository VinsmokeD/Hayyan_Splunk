# Hayyan SOC — Phase 2 Deployment Guide

Complete end-to-end setup for the AI SOC agent system.

## Prerequisites Checklist

- [ ] Python 3.10+ installed
- [ ] Splunk Enterprise running (Docker or on-prem)
- [ ] Google Gemini API key (free tier: https://aistudio.google.com)
- [ ] 4GB+ RAM available
- [ ] Network access to Splunk REST API (port 8089)

---

## Step 1: Install Dependencies

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Mac/Linux (Bash)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 2: Configure Environment

### Create .env File
```bash
# Copy template
cp .env.example .env
# Or on Windows: copy .env.example .env
```

### Edit .env with Your Values
```
GOOGLE_API_KEY=<your-gemini-api-key>
SPLUNK_HOST=192.168.56.1
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=Hayyan@2024!
SPLUNK_SCHEME=https
MODEL_NAME=gemini-2.5-flash
```

**Critical fields:**
- `GOOGLE_API_KEY` — Get from https://aistudio.google.com (free tier available)
- `SPLUNK_HOST` — Your Splunk server IP/hostname
- `SPLUNK_PORT` — Default 8089 (management API)

---

## Step 3: Verify Setup

### Run Verification Script
```bash
# Windows: python scripts/verify_setup.py
# Mac/Linux: python3 scripts/verify_setup.py
```

**Expected output:**
```
[OK] Python version
[OK] Virtual environment
[OK] Configuration (.env)
[OK] Dependencies
[OK] Directories
[OK] Splunk connectivity
[OK] Gemini API
```

If any checks fail, the script will tell you what to fix.

---

## Step 4: Initialize Knowledge Base

```bash
python soc_agents/knowledge/build_kb.py
```

This:
- Creates ChromaDB vector database
- Ingests MITRE ATT&CK techniques
- Loads SOC playbooks
- Initializes embeddings

**Output:**
```
Ingested 5 MITRE ATT&CK techniques
Ingested 3 SOC playbooks
Knowledge base initialized at: ./data/chroma_db
```

---

## Step 5: Start the System

### Option A: API Only (Web UI + REST)
```bash
# Windows: python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload
# Mac/Linux: python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload
```

**Access:**
- Web UI: http://localhost:8500
- API Docs: http://localhost:8500/docs
- WebSocket: ws://localhost:8500/ws/chat

### Option B: API + Streamlit Dashboard (Recommended)

**Terminal 1:** Start API
```bash
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload
```

**Terminal 2:** Start Streamlit
```bash
streamlit run soc_agents/ui/streamlit_app.py
```

**Access:**
- Web UI: http://localhost:8500
- Dashboard: http://localhost:8501

---

## Step 6: Test the System

### Quick Test via Web UI
1. Open http://localhost:8500
2. Wait for health status (should show "Splunk Connected")
3. Type: `"What alerts are currently fired?"`
4. Click Send
5. Watch agents work in real-time

### Test via API
```bash
# Check health
curl http://localhost:8500/api/health

# Get alerts
curl http://localhost:8500/api/alerts

# Send investigation request
curl -X POST http://localhost:8500/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Investigate IP 192.168.56.20"}'
```

### Test via Python
```python
from soc_agents.agents.soc_graph import soc_graph
from langchain_core.messages import HumanMessage

state = {"messages": [HumanMessage(content="Check Splunk health")]}
result = soc_graph.invoke(state)
print(result["report"])
```

---

## Troubleshooting

### Issue: "Splunk unreachable"
**Solution:**
1. Verify Splunk is running: `docker ps | grep splunk`
2. Check connectivity: `curl -k https://192.168.56.1:8089/services/server/info`
3. Verify credentials in .env
4. Check firewall (port 8089)

### Issue: "GOOGLE_API_KEY invalid"
**Solution:**
1. Visit https://aistudio.google.com
2. Generate new API key
3. Copy full key to GOOGLE_API_KEY in .env
4. Restart the API server

### Issue: "ChromaDB initialization fails"
**Solution:**
1. Delete data/chroma_db directory
2. Re-run: `python soc_agents/knowledge/build_kb.py`
3. Ensure write permissions on ./data

### Issue: "Port 8500 already in use"
**Solution:**
```bash
# Change API_PORT in .env to 8501 or 9000
# Or kill existing process:
# Windows: netstat -ano | findstr :8500
# Mac/Linux: lsof -i :8500 | grep LISTEN
```

### Issue: "langchain_google_genai not installed"
**Solution:**
```bash
pip install langchain-google-genai
```

---

## Configuration Options

### LLM Model Selection
Edit `.env` and change `MODEL_NAME`:
- `gemini-2.5-flash` — Fast & cheap (recommended)
- `gemini-2.5-pro` — Higher quality (slower)

### Splunk Scheme
- `https` — Default (self-signed certs ignored)
- `http` — For plain HTTP setups

### LangSmith Tracing (Optional)
For debugging agent runs:
```
LANGSMITH_API_KEY=your_langsmith_key
LANGSMITH_TRACING=true
```

Visit https://smith.langchain.com to see traces.

---

## File Structure

```
Hayyan_Splunk/
├── .env                          ← Configuration (git-ignored)
├── .env.example                  ← Template
├── requirements.txt              ← Dependencies
├── pyproject.toml                ← Project metadata
├── README.md                      ← Overview
├── CLAUDE.md                      ← Design doc
├── DEPLOYMENT.md                 ← This file
│
├── soc_agents/
│   ├── api/app.py               ← FastAPI server
│   ├── agents/soc_graph.py      ← LangGraph orchestration
│   ├── core/
│   │   ├── config.py
│   │   ├── models.py
│   │   └── splunk_client.py
│   ├── tools/splunk_tools.py    ← LangChain tools
│   ├── knowledge/build_kb.py    ← Knowledge base init
│   └── ui/
│       ├── index.html           ← Web interface
│       └── streamlit_app.py     ← Dashboard
│
├── scripts/
│   ├── setup.sh                 ← Init (Mac/Linux)
│   ├── run.sh                   ← Start (Mac/Linux)
│   ├── verify_setup.py          ← Verification
│   └── start_splunk_mcp.sh      ← Splunk MCP (future)
│
├── setup.ps1                     ← Init (Windows)
├── run.ps1                       ← Start (Windows)
│
├── tests/
│   ├── test_splunk_client.py
│   └── test_soc_graph.py
│
└── data/
    ├── chroma_db/               ← Vector store
    ├── checkpoints.sqlite       ← LangGraph state
    └── audit.log               ← Agent actions
```

---

## Next Steps

1. **Test with Real Alerts** → Fire an alert in Splunk and ask the agent to investigate
2. **Customize Playbooks** → Add your own detection rules to `build_kb.py`
3. **Enable Tracing** → Set up LangSmith to debug agent behavior
4. **Build Response Actions** → Configure automated responses (with approval)
5. **Integrate with SOAR** → Connect to your orchestration platform

---

## Support Resources

- **LangGraph Docs:** https://langchain-ai.github.io/langgraph/
- **Gemini API Guide:** https://ai.google.dev/
- **Splunk REST API:** https://docs.splunk.com/Documentation/Splunk/9.0.0/RESTAPI/
- **MITRE ATT&CK:** https://attack.mitre.org/

---

## Version Info

- **Phase:** 2.0 — Foundation Complete
- **LLM:** Gemini 2.5-Flash (default)
- **Orchestration:** LangGraph 0.0.33+
- **Web Framework:** FastAPI 0.109+
- **Last Updated:** 2026-04-18

