#!/usr/bin/env python3
"""
Hayyan SOC Lab - MISP to Splunk IOC Lookup Exporter.

Exports MISP attributes as a CSV lookup table and refreshes the Splunk lookup.

Usage:
    python scripts/misp_sync_splunk.py
    python scripts/misp_sync_splunk.py --dry-run

Output:
    data/misp_ioc_lookup.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _load_env() -> dict[str, str]:
    env_file = Path(__file__).parent.parent / ".env"
    cfg: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                cfg[key.strip()] = value.strip()
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
OUTPUTLOOKUP_CHUNK_ROWS = int(_env.get("SPLUNK_OUTPUTLOOKUP_CHUNK_ROWS", "100"))

OUTPUT_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = OUTPUT_DIR / "misp_ioc_lookup.csv"

WANTED_TYPES = {
    "ip-dst",
    "ip-src",
    "ip-dst|port",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email-src",
    "email-dst",
    "filename",
    "filename|md5",
    "filename|sha256",
}


def fetch_misp_iocs(limit: int = 5000) -> list[dict]:
    """Fetch IDS-ready attributes from MISP."""
    if not MISP_API_KEY:
        log.error("MISP_API_KEY not set. Add it to .env and retry.")
        sys.exit(1)

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {
        "returnFormat": "json",
        "type": list(WANTED_TYPES),
        "to_ids": True,
        "published": True,
        "limit": limit,
        "includeEventUuid": True,
        "includeEventTags": True,
        "includeGalaxy": False,
    }

    log.info("Fetching IOCs from MISP at %s ...", MISP_URL)
    try:
        response = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=headers,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=30,
        )
        response.raise_for_status()
        attrs = response.json().get("response", {}).get("Attribute", [])
        log.info("Fetched %d attributes from MISP.", len(attrs))
        return attrs
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to MISP at %s. Is it running?", MISP_URL)
        return []
    except Exception as exc:
        log.error("MISP fetch failed: %s", exc)
        return []


def normalize_to_lookup(attrs: list[dict]) -> list[dict]:
    """Convert raw MISP attributes to flat Splunk lookup rows."""
    rows: list[dict] = []
    sync_dt = datetime.now(timezone.utc)
    sync_time = sync_dt.isoformat().replace("+00:00", "Z")
    sync_epoch = int(sync_dt.timestamp())
    value_counts: dict[str, int] = {}

    for attr in attrs:
        value = attr.get("value", "")
        value_counts[value] = value_counts.get(value, 0) + 1

    for attr in attrs:
        tags = [tag.get("name", "") for tag in attr.get("Tag", [])]
        tlp = next((tag for tag in tags if tag.startswith("tlp:")), "tlp:amber")
        threat_tags = [tag for tag in tags if not tag.startswith("tlp:")]

        ioc_value = attr.get("value", "")
        ioc_type = attr.get("type", "")
        if "|" in ioc_type:
            ioc_value = ioc_value.split("|")[0]
            ioc_type = ioc_type.split("|")[0]

        rows.append(
            {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "threat_tags": "|".join(threat_tags[:5]),
                "tlp": tlp,
                "confidence": "high" if value_counts.get(attr.get("value", ""), 0) >= 3 else "medium",
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
            }
        )
    return rows


def write_csv(rows: list[dict]) -> int:
    """Write IOC lookup CSV for Splunk."""
    if not rows:
        log.warning("No IOC rows to write.")
        return 0

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    log.info("Wrote %d IOC rows to %s", len(rows), OUTPUT_CSV)
    return len(rows)


def _splunk_escape(value: str) -> str:
    """Escape a value for a double-quoted SPL eval string."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _chunks(items: list[dict], size: int) -> list[list[dict]]:
    size = max(1, size)
    return [items[index:index + size] for index in range(0, len(items), size)]


def _build_outputlookup_search(rows: list[dict], fields: list[str], filename: str, append: bool) -> str:
    append_parts = []
    for row in rows:
        eval_parts = [f'{field}="{_splunk_escape(row.get(field, ""))}"' for field in fields]
        append_parts.append(f'| append [ | makeresults | eval {", ".join(eval_parts)} ]')

    append_clause = " append=true" if append else ""
    return (
        "| makeresults count=0 "
        + " ".join(append_parts)
        + " | fields "
        + " ".join(fields)
        + f" | outputlookup{append_clause} {filename}"
    )


def _run_blocking_search(search: str, timeout: int = 90) -> bool:
    url = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs"
    try:
        response = requests.post(
            url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data={"search": search, "exec_mode": "blocking", "output_mode": "json"},
            verify=SPLUNK_VERIFY_SSL,
            timeout=timeout,
        )
        if response.status_code in (200, 201):
            return True
        log.warning("Splunk search job returned HTTP %s: %s", response.status_code, response.text[:300])
    except Exception as exc:
        log.warning("Splunk search job failed: %s", exc)
    return False


def push_lookup_via_outputlookup(csv_path: Path) -> bool:
    """Fallback: write lookup rows through controlled chunked outputlookup searches."""
    if not SPLUNK_PASSWORD:
        log.warning("SPLUNK_PASSWORD is not set; skipping outputlookup fallback.")
        return False

    try:
        with open(csv_path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except Exception as exc:
        log.warning("Could not read %s for outputlookup fallback: %s", csv_path, exc)
        return False

    if not rows:
        log.warning("No rows available for outputlookup fallback.")
        return False

    fields = list(rows[0].keys())
    chunks = _chunks(rows, OUTPUTLOOKUP_CHUNK_ROWS)
    log.info(
        "Writing lookup through outputlookup fallback in %d chunks of up to %d rows.",
        len(chunks),
        OUTPUTLOOKUP_CHUNK_ROWS,
    )

    for index, chunk in enumerate(chunks, start=1):
        search = _build_outputlookup_search(
            rows=chunk,
            fields=fields,
            filename=csv_path.name,
            append=index > 1,
        )
        if not _run_blocking_search(search):
            log.warning("outputlookup fallback failed on chunk %d/%d.", index, len(chunks))
            return False
        log.info("outputlookup chunk %d/%d written (%d rows).", index, len(chunks), len(chunk))

    log.info("Lookup written through outputlookup fallback (%d rows).", len(rows))
    return True


def push_to_splunk_lookup(csv_path: Path) -> bool:
    """Push the CSV to Splunk as a lookup table."""
    if not SPLUNK_PASSWORD:
        log.warning("SPLUNK_PASSWORD is not set; skipping Splunk lookup upload.")
        return False

    splunk_rest = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}"
    collection_url = f"{splunk_rest}/servicesNS/nobody/search/data/lookup-table-files"
    item_url = f"{collection_url}/{csv_path.name}"

    log.info("Pushing lookup to Splunk at %s ...", collection_url)
    try:
        with open(csv_path, "rb") as handle:
            response = requests.post(
                collection_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data={"name": csv_path.name, "output_mode": "json"},
                files={"eai:data": (csv_path.name, handle, "text/csv")},
                verify=SPLUNK_VERIFY_SSL,
                timeout=30,
            )
        if response.status_code in (200, 201):
            log.info("Lookup file uploaded to Splunk (HTTP %s)", response.status_code)
            return True
        log.warning("Splunk lookup create returned HTTP %s: %s", response.status_code, response.text[:200])

        with open(csv_path, "rb") as handle:
            update_response = requests.post(
                item_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data={"output_mode": "json"},
                files={"eai:data": (csv_path.name, handle, "text/csv")},
                verify=SPLUNK_VERIFY_SSL,
                timeout=30,
            )
        if update_response.status_code in (200, 201):
            log.info("Lookup file updated in Splunk (HTTP %s)", update_response.status_code)
            return True
        log.warning(
            "Splunk lookup update returned HTTP %s: %s",
            update_response.status_code,
            update_response.text[:200],
        )
    except Exception as exc:
        log.error("Splunk REST lookup push failed: %s", exc)

    if push_lookup_via_outputlookup(csv_path):
        return True

    configured = _env.get("SPLUNK_CONTAINER", "").strip()
    candidates = [configured] if configured else []
    candidates.extend(["hayyan-splunk", "splunk"])
    seen: set[str] = set()
    for container in candidates:
        if not container or container in seen:
            continue
        seen.add(container)
        lookup_dest = f"{container}:/opt/splunk/etc/apps/search/lookups/{csv_path.name}"
        try:
            subprocess.run(
                ["docker", "cp", str(csv_path), lookup_dest],
                check=True,
                capture_output=True,
                text=True,
            )
            log.info("Lookup copied via Docker fallback to %s", lookup_dest)
            return True
        except Exception as exc:
            log.warning("Splunk Docker fallback failed for container %s: %s", container, exc)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Export MISP IOCs to Splunk lookup")
    parser.add_argument("--dry-run", action="store_true", help="Print stats only, do not write or push")
    parser.add_argument("--limit", type=int, default=5000, help="Max attributes to fetch")
    args = parser.parse_args()

    start = time.time()
    attrs = fetch_misp_iocs(limit=args.limit)
    if not attrs:
        log.warning("No IOCs fetched. Check MISP connectivity and API key.")
        sys.exit(0)

    rows = normalize_to_lookup(attrs)
    seen = set()
    unique_rows = []
    for row in rows:
        key = (row["ioc_value"], row["ioc_type"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(row)
    log.info("Deduplicated: %d -> %d unique IOCs", len(rows), len(unique_rows))

    if args.dry_run:
        print(f"\n{'=' * 60}")
        print(f"DRY RUN - {len(unique_rows)} unique IOCs would be written to {OUTPUT_CSV}")
        print("Sample (first 5):")
        for row in unique_rows[:5]:
            print(f"  {row['ioc_type']:20s} {row['ioc_value']:40s} {row['misp_event_info'][:50]}")
        print(f"{'=' * 60}\n")
        return

    written = write_csv(unique_rows)
    if written > 0 and not push_to_splunk_lookup(OUTPUT_CSV):
        log.error("IOC CSV was written locally, but could not be delivered to Splunk lookup storage.")
        sys.exit(1)

    elapsed = time.time() - start
    log.info("Sync complete: %d IOCs in %.1fs", written, elapsed)


if __name__ == "__main__":
    main()
