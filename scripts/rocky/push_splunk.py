#!/usr/bin/env python3
"""
Hayyan SOC Lab — Splunk HEC Delivery
=====================================
Reads normalized JSONL findings and pushes them to Splunk HEC
into the vuln_scans index. Uses batched delivery with retry logic.

Usage:
    python3 push_splunk.py --input /opt/hayyan-scan/logs/normalized-RUN.jsonl \
                           --scan-id run-20260426-020000
"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error
import ssl

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config from environment ───────────────────────────────────────────────────
def _load_env():
    scan_home = Path(__file__).resolve().parent.parent
    env_files = [
        scan_home / "config" / "splunkhec.env",
        scan_home / ".env",
        Path("/opt/.env"),
    ]
    cfg = {}
    for env_file in env_files:
        if not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                cfg[k.strip()] = v.strip()
    return {**cfg, **os.environ}

_env = _load_env()

SPLUNK_HEC_URL = _env.get("SPLUNK_HEC_URL", "http://localhost:8086")
SPLUNK_HEC_TOKEN = _env.get("SPLUNK_HEC_TOKEN", "")
HEC_INDEX = "vuln_scans"
HEC_SOURCETYPE = "hayyan:vuln:scanner"
BATCH_SIZE = 50          # Events per HEC request
MAX_RETRIES = 3
RETRY_DELAY_S = 5        # Seconds between retries

# Disable SSL verification for self-signed certs in lab
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def build_hec_batch(records: list[dict]) -> str:
    """Encode records as HEC batch payload."""
    lines = []
    for rec in records:
        event_ts = rec.pop("time", time.time())
        payload = {
            "time": event_ts,
            "index": HEC_INDEX,
            "sourcetype": HEC_SOURCETYPE,
            "source": f"hayyan-scan:{rec.get('scanner','unknown')}",
            "host": rec.get("scanner_host", "rocky"),
            "event": rec,
        }
        lines.append(json.dumps(payload))
    return "\n".join(lines)


def send_hec_batch(batch_payload: str, attempt: int = 1) -> bool:
    """Send a batch to Splunk HEC. Returns True on success."""
    url = f"{SPLUNK_HEC_URL}/services/collector/event"
    data = batch_payload.encode("utf-8")
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            result = json.loads(body)
            if result.get("code") == 0:
                return True
            log.warning("[HEC] Non-zero response: %s", body[:200])
            return False
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error("[HEC] HTTP %s on attempt %d: %s", e.code, attempt, body[:200])
        return False
    except Exception as e:
        log.error("[HEC] Error on attempt %d: %s", attempt, e)
        return False


def push_findings(records: list[dict]) -> tuple[int, int]:
    """Push all records in batches. Returns (sent, failed) counts."""
    if not SPLUNK_HEC_TOKEN:
        log.error("SPLUNK_HEC_TOKEN not set. Create a token in Splunk UI → Settings → Data Inputs → HTTP Event Collector")
        return 0, len(records)

    sent = 0
    failed = 0

    for batch_start in range(0, len(records), BATCH_SIZE):
        batch = records[batch_start:batch_start + BATCH_SIZE]
        # Deep copy to avoid mutating original (we pop 'time' in build_hec_batch)
        batch_copy = [dict(r) for r in batch]
        payload = build_hec_batch(batch_copy)

        success = False
        for attempt in range(1, MAX_RETRIES + 1):
            if send_hec_batch(payload, attempt):
                success = True
                break
            if attempt < MAX_RETRIES:
                log.info("[HEC] Retry %d/%d in %ds...", attempt, MAX_RETRIES, RETRY_DELAY_S)
                time.sleep(RETRY_DELAY_S)

        if success:
            sent += len(batch)
            log.info("[HEC] Batch %d-%d sent (%d events)", batch_start + 1, batch_start + len(batch), len(batch))
        else:
            failed += len(batch)
            log.error("[HEC] Batch %d-%d FAILED after %d attempts", batch_start + 1, batch_start + len(batch), MAX_RETRIES)

    return sent, failed


def main():
    parser = argparse.ArgumentParser(description="Push normalized findings to Splunk HEC")
    parser.add_argument("--input", required=True, help="Normalized JSONL file")
    parser.add_argument("--scan-id", required=True, help="Scan run identifier")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    # Load normalized records
    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not records:
        log.info("No records to push (empty input file).")
        return

    log.info("Pushing %d findings (scan_id=%s) to Splunk HEC index=%s", len(records), args.scan_id, HEC_INDEX)
    sent, failed = push_findings(records)

    log.info("HEC delivery complete: %d sent, %d failed", sent, failed)
    if failed > 0:
        log.error("Some events failed delivery. Check Splunk HEC token and connectivity.")
        sys.exit(1)


if __name__ == "__main__":
    main()
