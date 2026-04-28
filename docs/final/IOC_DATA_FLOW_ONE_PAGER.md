# IOC Data Flow (One Page)

## Purpose

Provide deterministic IOC correlation from MISP into Splunk detections using a stable lookup artifact.

## End-to-End Flow

1. IOC creation in MISP
- IOC attributes are created in MISP events.
- For sync eligibility in this repo, attributes must be to_ids=true and part of published events.

2. Sync extraction
- scripts/misp_sync_splunk.py calls:
  - POST /attributes/restSearch on https://127.0.0.1:8443
- Filters include:
  - published=true
  - to_ids=true
  - type in allowed IOC families (ip, domain, hash, etc.)

3. Normalization
- MISP attributes are flattened into canonical IOC rows.
- Output columns include:
  - ioc_value, ioc_type, tlp, confidence, event metadata, sync_time

4. Lookup materialization
- CSV is written to data/misp_ioc_lookup.csv.
- Script attempts Splunk REST lookup upload.
- If REST upload fails in this Docker lab, script copies CSV directly to:
  - /opt/splunk/etc/apps/search/lookups/misp_ioc_lookup.csv

5. Detection usage
- Saved searches use inputlookup misp_ioc_lookup.csv in subsearches.
- IOC joins/correlation are performed against linux_web/sysmon and other telemetry indexes.

6. Analyst validation
- Validate lookup visibility with:
  - | inputlookup misp_ioc_lookup.csv | head 5
- Validate detections via dashboard and scheduled alerts.

## Why Lookup-Based Here

- Faster and simpler joins in detections.
- Avoids dependence on separate IOC indexing latency.
- Aligns with the validated state in this lab.

## Operational Gotchas

- Empty sync usually means event not published or to_ids=false.
- Host mismatch (localhost vs 127.0.0.1) can break MISP login/session/API usage.
- HEC protocol mismatch (https vs http on 8086) causes ingestion failures.
