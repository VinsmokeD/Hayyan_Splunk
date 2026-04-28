#!/usr/bin/env python3
"""
Validate the Task 2 Splunk operating layer.

Checks REST connectivity, creates required indexes when missing, verifies HEC,
and sends one structured test event to each Task 2 index.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ROOT = Path(__file__).resolve().parent.parent


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip().strip('"').strip("'")
    return {**env, **os.environ}


ENV = load_env()


def required(name: str) -> str:
    value = ENV.get(name, "").strip()
    placeholders = ("your_", "YOUR_", "changeme", "replace_me")
    if not value or any(token in value for token in placeholders):
        print(f"[ERROR] Required setting {name} is missing or still a placeholder.")
        print(f"        Add {name}=... to {ROOT / '.env'} or export it in the shell.")
        sys.exit(2)
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = ENV.get(name, str(default)).strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


SPLUNK_HOST = ENV.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(ENV.get("SPLUNK_PORT", "8088"))
SPLUNK_SCHEME = ENV.get("SPLUNK_SCHEME", "https").lower()
SPLUNK_USER = required("SPLUNK_USERNAME")
SPLUNK_PASS = required("SPLUNK_PASSWORD")
SPLUNK_VERIFY_SSL = env_bool("SPLUNK_VERIFY_SSL", False)
SPLUNK_REST = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}"

HEC_TOKEN = required("SPLUNK_HEC_TOKEN")
HEC_URL = ENV.get("SPLUNK_HEC_URL", "http://localhost:8086").rstrip("/")

SPLUNK_WEB_URL = ENV.get("SPLUNK_WEB_URL", "http://localhost:8080").rstrip("/")
MISP_URL = ENV.get("MISP_URL", "https://127.0.0.1:8443").rstrip("/")

TASK2_INDEXES = ["vuln_scans", "misp_iocs", "ai_soc_audit"]


def masked(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def rest(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{SPLUNK_REST}{path}"
    return requests.request(
        method,
        url,
        auth=(SPLUNK_USER, SPLUNK_PASS),
        verify=SPLUNK_VERIFY_SSL,
        timeout=kwargs.pop("timeout", 20),
        **kwargs,
    )


def test_hec(index: str, event_data: dict) -> tuple[int, str]:
    payload = {
        "index": index,
        "sourcetype": f"hayyan:{index}:test",
        "source": "task2_validation",
        "event": event_data,
    }
    response = requests.post(
        f"{HEC_URL}/services/collector/event",
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        json=payload,
        verify=False,
        timeout=8,
    )
    return response.status_code, response.text


def ensure_indexes() -> bool:
    print("\n2. Checking Task 2 indexes...")
    ok = True
    for index in TASK2_INDEXES:
        response = rest("GET", f"/services/data/indexes/{index}?output_mode=json")
        if response.status_code == 200:
            print(f"   [OK] Index '{index}' exists")
            continue
        if response.status_code == 404:
            print(f"   [MISSING] Creating index '{index}'...")
            created = rest(
                "POST",
                "/services/data/indexes",
                data={"name": index, "output_mode": "json"},
            )
            if created.status_code in (200, 201, 409):
                print(f"   [OK] Index '{index}' created or already present")
            else:
                ok = False
                print(f"   [FAIL] Could not create '{index}': HTTP {created.status_code}")
            continue
        ok = False
        print(f"   [FAIL] Index '{index}' check returned HTTP {response.status_code}")
    return ok


def ensure_hec() -> bool:
    print("\n3. Checking HEC service...")
    ok = True
    response = rest("GET", "/services/data/inputs/http?output_mode=json")
    if response.status_code == 200:
        inputs = response.json().get("entry", [])
        enabled = any(entry["content"].get("disabled") is False for entry in inputs)
        print(f"   [OK] HEC inputs visible ({len(inputs)} tokens, enabled={enabled})")
    else:
        ok = False
        print(f"   [WARN] HEC list check failed: HTTP {response.status_code}")

    enabled = rest(
        "POST",
        "/services/data/inputs/http/http",
        data={"disabled": "0", "output_mode": "json"},
    )
    if enabled.status_code in (200, 201):
        print("   [OK] HEC global service enabled")
    elif enabled.status_code not in (404, 409):
        print(f"   [WARN] HEC enable returned HTTP {enabled.status_code}")

    token_response = rest("GET", "/services/data/inputs/http/hayyan_hec_token?output_mode=json")
    if token_response.status_code == 404:
        created = rest(
            "POST",
            "/services/data/inputs/http",
            data={
                "name": "hayyan_hec_token",
                "token": HEC_TOKEN,
                "index": "vuln_scans",
                "indexes": ",".join([*TASK2_INDEXES, "main"]),
                "disabled": "0",
                "output_mode": "json",
            },
        )
        if created.status_code in (200, 201, 409):
            print("   [OK] HEC token created or already present")
        else:
            ok = False
            print(f"   [FAIL] HEC token create failed: HTTP {created.status_code}")
    else:
        print("   [OK] HEC token stanza already exists")
    return ok


def main() -> int:
    print("=== Hayyan SOC Task 2 - Splunk Validation ===\n")
    print(f"REST API : {SPLUNK_REST}")
    print(f"HEC URL  : {HEC_URL}")
    print(f"HEC token: {masked(HEC_TOKEN)}")

    exit_code = 0

    print("\n1. REST API connectivity...")
    try:
        response = rest("GET", "/services/server/info?output_mode=json")
        if response.status_code == 200:
            info = response.json()["entry"][0]["content"]
            print(f"   [OK] Splunk {info.get('version')} build {info.get('build')}")
        else:
            print(f"   [FAIL] Status {response.status_code}: {response.text[:160]}")
            return 1
    except Exception as exc:
        print(f"   [FAIL] {exc}")
        return 1

    if not ensure_indexes():
        exit_code = 1
    if not ensure_hec():
        exit_code = 1

    print("\n4. Testing HEC ingestion...")
    test_events = {
        "vuln_scans": {
            "scanner": "validation",
            "target": "192.168.56.20",
            "severity": "high",
            "cveid": "CVE-2024-TEST",
            "cvssscore": 8.5,
            "service": "http",
            "source": "task2_validation",
        },
        "misp_iocs": {
            "ioc_type": "ip-dst",
            "ioc_value": "185.220.101.45",
            "category": "Network activity",
            "source": "task2_validation",
        },
        "ai_soc_audit": {
            "event_type": "tool_call_complete",
            "tool_name": "run_splunk_query",
            "status": "success",
            "elapsed_ms": 1234,
            "source": "task2_validation",
        },
    }
    for index, event in test_events.items():
        code, text = test_hec(index, event)
        if code == 200:
            print(f"   [OK] HEC -> '{index}' ingestion works")
        else:
            exit_code = 1
            print(f"   [FAIL] HEC '{index}': HTTP {code} -> {text[:160]}")

    print("\n5. Checking HayyanSOC app...")
    response = rest("GET", "/services/apps/local/HayyanSOC?output_mode=json")
    if response.status_code == 200:
        entry = response.json()["entry"][0]["content"]
        print(f"   [OK] HayyanSOC app loaded (version={entry.get('version', 'N/A')})")
    else:
        print(f"   [WARN] HayyanSOC app not found (HTTP {response.status_code})")
        print("          Copy splunk_config into /opt/splunk/etc/apps/HayyanSOC and restart Splunk.")

    print(
        "\n=== Access Links ===\n"
        f"Splunk Web UI : {SPLUNK_WEB_URL}\n"
        f"Splunk REST   : {SPLUNK_REST}\n"
        f"MISP UI       : {MISP_URL}\n"
        f"HEC Token     : {masked(HEC_TOKEN)}\n"
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
