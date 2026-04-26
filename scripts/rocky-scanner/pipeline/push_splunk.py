#!/usr/bin/env python3
"""
Push normalized vulnerability findings to Splunk via HEC (HTTP Event Collector).

Each finding becomes one Splunk event with proper timestamp and sourcetype.
Batches up to 100 events per request to stay within HEC limits.
"""
import argparse
import json
import logging
import sys
import time
from typing import Iterator

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)

BATCH_SIZE = 100
HEC_TIMEOUT = 15


def iter_findings(path: str) -> Iterator[dict]:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Skipping malformed line in %s", path)


def build_hec_event(finding: dict, index: str, sourcetype: str) -> dict:
    return {
        "time": finding.get("time", int(time.time())),
        "host": finding.get("target", "unknown"),
        "source": f"hayyan-scan:{finding.get('scanner','unknown')}",
        "sourcetype": sourcetype,
        "index": index,
        "event": finding,
    }


def push_batch(batch: list[dict], hec_url: str, token: str) -> bool:
    payload = "\n".join(json.dumps(e) for e in batch)
    try:
        resp = requests.post(
            f"{hec_url.rstrip('/')}/services/collector/event",
            headers={"Authorization": f"Splunk {token}"},
            data=payload,
            verify=False,
            timeout=HEC_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") != 0:
            log.error("HEC error: %s", result)
            return False
        return True
    except requests.exceptions.ConnectionError as e:
        log.error("Cannot connect to Splunk HEC at %s: %s", hec_url, e)
        return False
    except requests.exceptions.HTTPError as e:
        log.error("HEC HTTP error: %s — response: %s", e, e.response.text if e.response else "")
        return False
    except Exception as e:
        log.error("HEC push error: %s", e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Push scan findings to Splunk HEC")
    parser.add_argument("--normalized", required=True, help="Path to normalized JSONL file")
    parser.add_argument("--hec-url", default="https://192.168.56.1:8088")
    parser.add_argument("--hec-token", required=True)
    parser.add_argument("--index", default="vuln_scans")
    parser.add_argument("--sourcetype", default="hayyan:vuln:scan")
    args = parser.parse_args()

    batch: list[dict] = []
    pushed = 0
    failed = 0

    for finding in iter_findings(args.normalized):
        batch.append(build_hec_event(finding, args.index, args.sourcetype))
        if len(batch) >= BATCH_SIZE:
            if push_batch(batch, args.hec_url, args.hec_token):
                pushed += len(batch)
            else:
                failed += len(batch)
            batch = []

    if batch:
        if push_batch(batch, args.hec_url, args.hec_token):
            pushed += len(batch)
        else:
            failed += len(batch)

    print(f"[push_splunk] {pushed} events pushed, {failed} failed → index={args.index}")
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
