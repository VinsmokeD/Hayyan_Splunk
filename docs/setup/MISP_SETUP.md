# MISP Setup Guide — Hayyan SOC Lab

## Overview
MISP (Malware Information Sharing Platform) is the threat intelligence backbone of the Hayyan SOC.
It holds known-bad IOCs (IPs, domains, hashes), supports external feed ingestion, and is queried
by the AI SOC agent and Splunk during investigations.

---

## Step 1: Start MISP

```powershell
# On the host machine (Windows, in the Hayyan_Splunk directory)
docker compose -f docker-compose.misp.yml up -d

# Verify all three containers are running
docker ps | Select-String "hayyan-misp"
```

Expected containers:
- `hayyan-misp` (main MISP application)
- `hayyan-misp-db` (MySQL 8.0)
- `hayyan-misp-redis` (Redis 7)

> [!NOTE]
> First startup takes **3-5 minutes** as MISP initializes the database and generates keys.
> Monitor with: `docker logs -f hayyan-misp`

---

## Step 2: Initial Login & Password Change

1. Open: **https://127.0.0.1:8443**
2. Accept the self-signed certificate warning
3. Login: `admin@admin.test` / `MispAdmin2026!`
4. If login fails, reset via container CLI before troubleshooting anything else.

---

## Step 3: Get Your API Key

1. Administration → Auth Keys → Add Authentication Key
2. Set description: `splunk-integration`
3. Set permissions: Read Only (for Splunk sync user)
4. Copy the API key — you only see it once!

```env
# Add to your .env file:
MISP_API_KEY=your_key_here
MISP_URL=https://127.0.0.1:8443
MISP_VERIFY_SSL=false
MISP_ALLOW_WRITE=false
```

Keep `MISP_ALLOW_WRITE=false` during normal demos. The AI agent can draft MISP events with `create_misp_event`, but live event creation stays blocked until Mahmoud explicitly approves the exact write and flips this setting.

---

## Step 4: Bootstrap Feeds

```bash
# Run the automated feed bootstrapper
bash scripts/misp_setup.sh
```

This script:
- Waits for MISP to be healthy
- Enables CIRCL, URLhaus, Feodo Tracker, MalwareBazaar feeds
- Triggers initial feed pull (runs in background, ~1-5 min)

**Manual verification in MISP UI:**
- Sync Actions → List Feeds → verify feeds show "Enabled"
- Sync Actions → Fetch All Feeds → wait and check event count

---

## Step 5: Sync IOCs to Splunk

```bash
# Export IOC lookup CSV (run on Windows host)
.venv\Scripts\python.exe scripts\misp_sync_splunk.py

# Dry run first to see what will be exported:
.venv\Scripts\python.exe scripts\misp_sync_splunk.py --dry-run
```

Output: `data/misp_ioc_lookup.csv` — this file is used by Splunk saved searches.

**Apply the Splunk lookup:**
1. Splunk UI → Settings → Lookups → Lookup table files → Upload
2. Upload `data/misp_ioc_lookup.csv` with name `misp_ioc_lookup`
3. Settings → Lookups → Lookup definitions → New → Name: `misp_ioc_lookup`

---

## Step 6: Apply Splunk Indexes

```powershell
# Apply indexes inside Splunk container
Get-Content splunk_config\indexes.conf | docker exec -i hayyan-splunk bash -c "cat >> /opt/splunk/etc/system/local/indexes.conf"
docker exec hayyan-splunk /opt/splunk/bin/splunk restart
```

---

## Step 7: Apply Threat Dashboard

1. Splunk UI → Dashboards → Create New Dashboard
2. Click "Source" (XML editor)
3. Paste content from `splunk_config/threat_dashboard.xml`
4. Save as: "Hayyan SOC — Threat-Informed Defense"

---

## Step 8: Apply Risk-Adjusted Alerts

```powershell
# Apply saved searches (detection rules)
Get-Content splunk_config\risk_adjusted_alerts.conf | docker exec -i hayyan-splunk bash -c "cat >> /opt/splunk/etc/system/local/savedsearches.conf"
docker exec hayyan-splunk /opt/splunk/bin/splunk restart
```

---

## Step 9: Test the Integration

```bash
# Verify MISP API is working
curl -sk -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" \
    https://127.0.0.1:8443/servers/getVersion

# Ask the AI agent about a known-bad IP
# In the Streamlit UI:
"Look up 185.220.101.45 in MISP threat intel"
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| MISP UI not reachable | `docker logs hayyan-misp` — check for DB connection errors |
| API returns 403 | API key wrong or expired — regenerate in UI |
| Feeds show 0 events | Run Sync Actions → Fetch All Feeds manually in UI |
| IOC lookup empty in Splunk | Re-run `scripts/misp_sync_splunk.py` and re-upload CSV |
| misp_sync_splunk.py times out | MISP URL/port wrong in .env — check `MISP_URL=https://127.0.0.1:8443` |

---

## Architecture Notes

- MISP is accessible only on the host machine (Docker port `8443:443`)
- The AI agent queries MISP directly via Python `requests` (bypasses Splunk)
- Splunk uses the exported CSV lookup for fast join operations in saved searches
- Critical scan findings are automatically mirrored to MISP via `push_misp.py`
