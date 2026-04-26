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
import sys
import time
import argparse
from datetime import datetime
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

MISP_URL = _env.get("MISP_URL", "https://localhost:8443").rstrip("/")
MISP_API_KEY = _env.get("MISP_API_KEY", "")
MISP_VERIFY_SSL = _env.get("MISP_VERIFY_SSL", "false").lower() == "true"
SPLUNK_HOST = _env.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(_env.get("SPLUNK_PORT", "8088"))
SPLUNK_USERNAME = _env.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = _env.get("SPLUNK_PASSWORD", "Hayyan@2024!")
SPLUNK_VERIFY_SSL = _env.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"

OUTPUT_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = OUTPUT_DIR / "misp_ioc_lookup.csv"

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
            "sync_time": datetime.utcnow().isoformat() + "Z",
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


def push_to_splunk_lookup(csv_path: Path) -> bool:
    """Push the CSV to Splunk as a lookup table via REST API."""
    # Upload to Splunk's lookup files endpoint
    splunk_rest = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
    url = f"{splunk_rest}/servicesNS/nobody/search/data/lookup-table-files"

    log.info("Pushing lookup to Splunk at %s ...", url)
    try:
        with open(csv_path, "rb") as f:
            resp = requests.post(
                url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                files={"eai:data": ("misp_ioc_lookup.csv", f, "text/csv")},
                verify=SPLUNK_VERIFY_SSL,
                timeout=30,
            )
        if resp.status_code in (200, 201, 409):  # 409 = already exists (update needed)
            log.info("Lookup file uploaded to Splunk (HTTP %s)", resp.status_code)
            return True
        else:
            log.warning("Splunk lookup upload returned HTTP %s: %s", resp.status_code, resp.text[:200])
            return False
    except Exception as e:
        log.error("Splunk push failed: %s", e)
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
        push_to_splunk_lookup(OUTPUT_CSV)

    elapsed = time.time() - start
    log.info("Sync complete: %d IOCs in %.1fs", written, elapsed)


if __name__ == "__main__":
    main()
