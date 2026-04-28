#!/usr/bin/env python3
"""
Hayyan SOC Lab — MISP → Splunk IOC Lookup Exporter
====================================================
Exports MISP attributes as a CSV lookup table and pushes it to Splunk.
Run via cron or systemd timer for continuous IOC freshness.

Usage:
    python3 scripts/misp_sync_splunk.py
    python3 scripts/misp_sync_splunk.py --dry-run    (print CSV only, no push)

Output:
    - data/misp_ioc_lookup.csv  (for Splunk lookup table)
    - Optionally pushes to Splunk via REST API for automatic lookup refresh
"""
import csv
import json
import logging
import os
import subprocess
import sys
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config (from .env or environment) ────────────────────────────────────────
def _load_env():
    env_file = Path(__file__).parent.parent / ".env"
    cfg = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                cfg[k.strip()] = v.strip()
    return cfg

_env = {**_load_env(), **os.environ}

MISP_URL = _env.get("MISP_URL", "https://127.0.0.1:8443").rstrip("/")
MISP_API_KEY = _env.get("MISP_API_KEY", "")
MISP_VERIFY_SSL = _env.get("MISP_VERIFY_SSL", "false").lower() == "true"
SPLUNK_HOST = _env.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(_env.get("SPLUNK_PORT", "8088"))
SPLUNK_SCHEME = _env.get("SPLUNK_SCHEME", "https").lower()
SPLUNK_USERNAME = _env.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = _env.get("SPLUNK_PASSWORD", "")
SPLUNK_VERIFY_SSL = _env.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"

OUTPUT_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = OUTPUT_DIR / "misp_ioc_lookup.csv"
OUTPUTLOOKUP_MAX_ROWS = int(_env.get("SPLUNK_OUTPUTLOOKUP_MAX_ROWS", "200"))

# IOC attribute types to pull (skip internal-only types)
WANTED_TYPES = {
    "ip-dst", "ip-src", "ip-dst|port",
    "domain", "hostname", "url",
    "md5", "sha1", "sha256",
    "email-src", "email-dst",
    "filename", "filename|md5", "filename|sha256",
}

# ── MISP fetch ────────────────────────────────────────────────────────────────
def fetch_misp_iocs(limit: int = 5000) -> list[dict]:
    """Fetch attributes from MISP REST API."""
    if not MISP_API_KEY:
        log.error("MISP_API_KEY not set. Add to .env and retry.")
        sys.exit(1)

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {
        "returnFormat": "json",
        "type": list(WANTED_TYPES),
        "to_ids": True,          # Only IDS-flagged (confirmed malicious)
        "published": True,
        "limit": limit,
        "includeEventUuid": True,
        "includeEventTags": True,
        "includeGalaxy": False,  # Skip galaxy context (too verbose)
    }

    log.info("Fetching IOCs from MISP at %s ...", MISP_URL)
    try:
        resp = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=headers,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=30,
        )
        resp.raise_for_status()
        attrs = resp.json().get("response", {}).get("Attribute", [])
        log.info("Fetched %d attributes from MISP.", len(attrs))
        return attrs
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to MISP at %s. Is it running?", MISP_URL)
        return []
    except Exception as e:
        log.error("MISP fetch failed: %s", e)
        return []


def normalize_to_lookup(attrs: list[dict]) -> list[dict]:
    """Convert raw MISP attributes to flat CSV rows."""
    rows = []
    sync_dt = datetime.now(timezone.utc)
    sync_time = sync_dt.isoformat().replace("+00:00", "Z")
    sync_epoch = int(sync_dt.timestamp())
    for attr in attrs:
        # Extract tags
        tags = [t.get("name", "") for t in attr.get("Tag", [])]
        tlp = next((t for t in tags if t.startswith("tlp:")), "tlp:amber")
        threat_tags = [t for t in tags if not t.startswith("tlp:")]

        # Normalize IP|port type
        ioc_value = attr.get("value", "")
        ioc_type = attr.get("type", "")
        if "|" in ioc_type:
            # e.g. "ip-dst|port" → split value "1.2.3.4|443" → use IP only
            ioc_value = ioc_value.split("|")[0]
            ioc_type = ioc_type.split("|")[0]

        rows.append({
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "threat_tags": "|".join(threat_tags[:5]),  # cap length
            "tlp": tlp,
            "confidence": "high" if len([a for a in attrs if a.get("value") == attr.get("value")]) >= 3 else "medium",
            "misp_event_id": attr.get("event_id", ""),
            "misp_event_uuid": attr.get("event_uuid", ""),
            "misp_event_info": attr.get("Event", {}).get("info", "")[:120],
            "first_seen": attr.get("first_seen", ""),
            "last_seen": attr.get("last_seen", ""),
            "timestamp": attr.get("timestamp", ""),
            "category": attr.get("category", ""),
            "to_ids": str(attr.get("to_ids", False)),
            "sync_time": sync_time,
            "sync_epoch": sync_epoch,
        })
    return rows


def write_csv(rows: list[dict]) -> int:
    """Write IOC lookup CSV for Splunk."""
    if not rows:
        log.warning("No IOC rows to write.")
        return 0

    fieldnames = list(rows[0].keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log.info("Wrote %d IOC rows to %s", len(rows), OUTPUT_CSV)
    return len(rows)


def _splunk_escape(value: str) -> str:
    """Escape a value for a double-quoted SPL eval string."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def push_lookup_via_outputlookup(csv_path: Path) -> bool:
    """Fallback: write a small lookup file through a controlled outputlookup search."""
    try:
        with open(csv_path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except Exception as exc:
        log.warning("Could not read %s for outputlookup fallback: %s", csv_path, exc)
        return False

    if not rows:
        log.warning("No rows available for outputlookup fallback.")
        return False
    if len(rows) > OUTPUTLOOKUP_MAX_ROWS:
        log.warning(
            "Skipping outputlookup fallback: %d rows exceeds SPLUNK_OUTPUTLOOKUP_MAX_ROWS=%d.",
            len(rows),
            OUTPUTLOOKUP_MAX_ROWS,
        )
        return False

    fields = list(rows[0].keys())
    append_parts = []
    for row in rows:
        eval_parts = [f'{field}="{_splunk_escape(row.get(field, ""))}"' for field in fields]
        append_parts.append(f'| append [ | makeresults | eval {", ".join(eval_parts)} ]')

    search = (
        "| makeresults count=0 "
        + " ".join(append_parts)
        + " | fields "
        + " ".join(fields)
        + f" | outputlookup {csv_path.name}"
    )
    url = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs"
    try:
        response = requests.post(
            url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data={
                "search": search,
                "exec_mode": "blocking",
                "output_mode": "json",
            },
            verify=SPLUNK_VERIFY_SSL,
            timeout=60,
        )
        if response.status_code in (200, 201):
            log.info("Lookup written through outputlookup fallback (%d rows).", len(rows))
            return True
        log.warning("outputlookup fallback returned HTTP %s: %s", response.status_code, response.text[:200])
    except Exception as exc:
        log.warning("outputlookup fallback failed: %s", exc)
    return False


def push_to_splunk_lookup(csv_path: Path) -> bool:
    """Push the CSV to Splunk as a lookup table via REST API."""
    if not SPLUNK_PASSWORD:
        log.warning("SPLUNK_PASSWORD is not set; skipping Splunk REST lookup upload.")
        return False

    # Upload to Splunk's lookup files endpoint
    splunk_rest = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}"
    collection_url = f"{splunk_rest}/servicesNS/nobody/search/data/lookup-table-files"
    item_url = f"{collection_url}/{csv_path.name}"

    log.info("Pushing lookup to Splunk at %s ...", collection_url)
    try:
        with open(csv_path, "rb") as f:
            resp = requests.post(
                collection_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data={"name": csv_path.name, "output_mode": "json"},
                files={"eai:data": ("misp_ioc_lookup.csv", f, "text/csv")},
                verify=SPLUNK_VERIFY_SSL,
                timeout=30,
            )
        if resp.status_code in (200, 201):
            log.info("Lookup file uploaded to Splunk (HTTP %s)", resp.status_code)
            return True
        log.warning("Splunk lookup create returned HTTP %s: %s", resp.status_code, resp.text[:200])

        # Existing lookup files are updated through the named endpoint.
        with open(csv_path, "rb") as f:
            update_resp = requests.post(
                item_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data={"output_mode": "json"},
                files={"eai:data": ("misp_ioc_lookup.csv", f, "text/csv")},
                verify=SPLUNK_VERIFY_SSL,
                timeout=30,
            )
        if update_resp.status_code in (200, 201):
            log.info("Lookup file updated in Splunk (HTTP %s)", update_resp.status_code)
            return True
        log.warning(
            "Splunk lookup update returned HTTP %s: %s",
            update_resp.status_code,
            update_resp.text[:200],
        )
    except Exception as e:
        log.error("Splunk push failed: %s", e)

    if push_lookup_via_outputlookup(csv_path):
        return True

    # Fallback for local Docker lab where REST upload may reject multipart handling.
    configured = _env.get("SPLUNK_CONTAINER", "").strip()
    candidates = [configured] if configured else []
    candidates.extend(["hayyan-splunk", "splunk"])
    for container in [c for i, c in enumerate(candidates) if c and c not in candidates[:i]]:
        lookup_dest = f"{container}:/opt/splunk/etc/apps/search/lookups/{csv_path.name}"
        try:
            subprocess.run(["docker", "cp", str(csv_path), lookup_dest], check=True, capture_output=True, text=True)
            log.info("Lookup copied via Docker fallback to %s", lookup_dest)
            return True
        except Exception as e:
            log.warning("Splunk Docker fallback failed for container %s: %s", container, e)
    return False


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Export MISP IOCs to Splunk lookup")
    parser.add_argument("--dry-run", action="store_true", help="Print stats only, do not write or push")
    parser.add_argument("--limit", type=int, default=5000, help="Max attributes to fetch (default 5000)")
    args = parser.parse_args()

    start = time.time()
    attrs = fetch_misp_iocs(limit=args.limit)

    if not attrs:
        log.warning("No IOCs fetched. Check MISP connectivity and API key.")
        sys.exit(0)

    rows = normalize_to_lookup(attrs)

    # Deduplicate by ioc_value
    seen = set()
    unique_rows = []
    for row in rows:
        key = (row["ioc_value"], row["ioc_type"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(row)
    log.info("Deduplicated: %d → %d unique IOCs", len(rows), len(unique_rows))

    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"DRY RUN — {len(unique_rows)} unique IOCs would be written to {OUTPUT_CSV}")
        print(f"Sample (first 5):")
        for row in unique_rows[:5]:
            print(f"  {row['ioc_type']:20s} {row['ioc_value']:40s} {row['misp_event_info'][:50]}")
        print(f"{'='*60}\n")
        return

    written = write_csv(unique_rows)
    if written > 0:
        if not push_to_splunk_lookup(OUTPUT_CSV):
            log.error("IOC CSV was written locally, but could not be delivered to Splunk lookup storage.")
            sys.exit(1)

    elapsed = time.time() - start
    log.info("Sync complete: %d IOCs in %.1fs", written, elapsed)


if __name__ == "__main__":
    main()
