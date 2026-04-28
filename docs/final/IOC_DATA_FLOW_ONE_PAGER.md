# IOC Data Flow - One Page

## Purpose

Provide deterministic IOC correlation from MISP into Splunk detections using a stable lookup artifact.

## End-to-End Flow

1. IOC attributes are created or synced into MISP.
2. Eligible attributes are published and marked `to_ids=true`.
3. `scripts/misp_sync_splunk.py` calls MISP `/attributes/restSearch`.
4. Attributes are flattened into canonical lookup rows.
5. Rows are written to `data/misp_ioc_lookup.csv`.
6. Splunk lookup refresh is attempted through REST upload.
7. If REST upload is rejected, controlled chunked `outputlookup` jobs refresh the lookup.
8. Detections and hunts consume the lookup with `inputlookup`.

## Current Validation

April 28, 2026 validation:

- 5,000 MISP attributes fetched.
- 4,995 unique IOCs after deduplication.
- Lookup refresh succeeded through 50 outputlookup chunks.
- Splunk query `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type` returned data.

## Canonical Lookup Columns

- `ioc_value`
- `ioc_type`
- `threat_tags`
- `tlp`
- `confidence`
- `misp_event_id`
- `misp_event_uuid`
- `misp_event_info`
- `first_seen`
- `last_seen`
- `timestamp`
- `category`
- `to_ids`
- `sync_time`
- `sync_epoch`

## Validation SPL

```spl
| inputlookup misp_ioc_lookup.csv | stats count by ioc_type | sort -count
```

```spl
index=linux_web
[ | inputlookup misp_ioc_lookup.csv
  | where ioc_type="ip-src" OR ioc_type="ip-dst"
  | rename ioc_value as clientip
  | fields clientip ]
| stats count by clientip
```

## Why Lookup-Based Here

- Faster joins for laptop-scale Splunk.
- Easy to explain during an internship demo.
- No dependency on a separate IOC indexing schedule during detection.
- Compatible with retrospective hunts through `sync_epoch`.

## Operational Gotchas

- Empty sync usually means events are not published or attributes are not `to_ids=true`.
- Host mismatch between `localhost`, `127.0.0.1`, and `192.168.56.1` can break cross-node flows.
- HEC protocol mismatch on `8086` causes ingestion failures.
- External LLM chat tests require explicit approval before sending lab context to the provider.
