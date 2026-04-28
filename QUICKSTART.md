# Hayyan SOC — Quick Start (5 Minutes)

Get the AI SOC agent running in 5 minutes.

## TL;DR

```bash
# 1. Install
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env: add GOOGLE_API_KEY, Splunk credentials

# 3. Initialize
python soc_agents/knowledge/build_kb.py

# 4. Run
python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload

# 5. Access
# Open: http://localhost:8500
```

---

## What You Get

✅ **Web UI** — Chat with AI agents at http://localhost:8500  
✅ **REST API** — HTTP endpoints for integrations  
✅ **WebSocket** — Real-time streaming responses  
✅ **Dashboard** — Streamlit monitoring (optional)  
✅ **Splunk Integration** — Queries 5 indexes automatically  
✅ **MITRE Mapping** — Threats tagged with ATT&CK techniques  
✅ **Markdown Reports** — Professional incident reports  

---

## Example Queries

Type these in the web UI:

1. **"What alerts are fired?"**
   - Agent: Alert Triage Specialist
   - Returns: Current alerts with severity

2. **"Investigate IP 192.168.56.20"**
   - Agent: Investigator
   - Returns: Timeline, findings, MITRE mapping

3. **"Show failed login attempts"**
   - Agent: Query Specialist
   - Returns: EventCode=4625 timeline with stats

4. **"Check Splunk health"**
   - Agent: Any (routed automatically)
   - Returns: Index counts, connectivity status

---

## Where to Go From Here

**Full Setup:** See [DEPLOYMENT.md](DEPLOYMENT.md)  
**Architecture:** See [CLAUDE.md](CLAUDE.md)  
**Troubleshooting:** See [README.md](README.md#troubleshooting)  

---

## Fastest Path to Success

1. Verify Splunk is running: `curl -k https://192.168.56.1:8088/services/server/info`
2. Get Gemini API key: https://aistudio.google.com (free)
3. Add to .env: `GOOGLE_API_KEY=your_key`
4. Run: `python -m uvicorn soc_agents.api.app:app --host 0.0.0.0 --port 8500 --reload`
5. Open browser: http://localhost:8500

That's it! The agents do the rest.

---

**Status:** Phase 2.0 | Ready for Production | Built with ❤️ for Hayyan Horizons
