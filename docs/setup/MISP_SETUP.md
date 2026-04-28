# MISP Setup Guide - Hayyan SOC Lab

## Overview

MISP is the threat intelligence backbone of the Hayyan SOC. It stores known-bad IOCs, supports feed ingestion, and supplies context to Splunk searches and the AI SOC agent.

## Start MISP

```powershell
docker compose -f docker-compose.misp.yml up -d
```

Open:

```text
https://127.0.0.1:8443
```

First startup can take several minutes while MISP initializes its database.

## API Key

Create a dedicated integration key in MISP and set:

```env
MISP_URL=https://127.0.0.1:8443
MISP_API_KEY=your_misp_api_key_here
MISP_VERIFY_SSL=false
MISP_ALLOW_WRITE=false
```

Keep `MISP_ALLOW_WRITE=false` for normal demos. The AI agent and scanner pipeline may draft or prepare MISP context, but live MISP event creation requires explicit approval.

## Feed Bootstrap

```bash
bash scripts/misp_setup.sh
```

Recommended initial feeds:

- CIRCL default feed
- Abuse.ch URLhaus
- Abuse.ch Feodo Tracker
- MalwareBazaar
- OTX public pulse feed

## Sync IOCs to Splunk

Dry run:

```powershell
python scripts/misp_sync_splunk.py --dry-run
```

Full sync:

```powershell
python scripts/misp_sync_splunk.py
```

Validated on April 28, 2026:

- MISP returned 5,000 attributes.
- Deduplication produced 4,995 unique IOCs.
- `data/misp_ioc_lookup.csv` was written locally.
- Splunk lookup refresh succeeded through chunked `outputlookup` fallback.

Verify in Splunk:

```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type | sort -count
```

## Why Lookup-Based Sync

The `misp_ioc_lookup.csv` approach keeps detections fast and easy to explain. Saved searches can use `inputlookup` instead of repeatedly scanning a large IOC index. This fits the laptop-sized lab while still looking like a real SOC enrichment pattern.

## Splunk Integration Checks

```spl
| inputlookup misp_ioc_lookup.csv | head 5
```

```spl
index=linux_web
[ | inputlookup misp_ioc_lookup.csv
  | where ioc_type="ip-src" OR ioc_type="ip-dst"
  | rename ioc_value as clientip
  | fields clientip ]
| stats count by clientip
```

## Troubleshooting

| Problem | Fix |
|---|---|
| MISP UI not reachable | Check `docker compose -f docker-compose.misp.yml ps` and container logs. |
| API returns 403 | Regenerate the MISP auth key and update `.env`. |
| Dry run returns 0 IOCs | Confirm feeds have been fetched and attributes are published with `to_ids=true`. |
| Splunk REST lookup upload fails | Expected in this lab; the script falls back to chunked `outputlookup`. |
| Lookup still empty | Re-run `python scripts/misp_sync_splunk.py` and check for chunk progress messages. |

## Architecture Notes

- MISP runs on the host at `https://127.0.0.1:8443`.
- Splunk uses the exported CSV lookup for correlation and retrospective hunts.
- Rocky scanner-side MISP writes are disabled unless `MISP_ALLOW_WRITE=true`.
- The AI chat workflow should only be tested with external providers after explicit approval to send lab context.
