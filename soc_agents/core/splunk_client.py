import json
import time
import urllib3
import requests
from typing import Any
from .config import get_settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkClient:
    """Thin REST client for Splunk management API (port 8089)."""

    def __init__(self):
        cfg = get_settings()
        self.base_url = f"{cfg.splunk_scheme}://{cfg.splunk_host}:{cfg.splunk_port}"
        self.auth = (cfg.splunk_username, cfg.splunk_password)
        self.verify = cfg.splunk_verify_ssl
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = self.verify

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def run_search(self, spl: str, earliest: str = "-24h", latest: str = "now", max_results: int = 100) -> list[dict]:
        """Execute a blocking SPL search and return results as a list of dicts."""
        # Create job
        resp = self.session.post(
            self._url("/services/search/jobs"),
            data={
                "search": f"search {spl}" if not spl.strip().startswith("search") else spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
        )
        resp.raise_for_status()
        sid = resp.json()["sid"]

        # Poll until done
        for _ in range(60):
            status_resp = self.session.get(
                self._url(f"/services/search/jobs/{sid}"),
                params={"output_mode": "json"},
            )
            status_resp.raise_for_status()
            dispatch_state = status_resp.json()["entry"][0]["content"]["dispatchState"]
            if dispatch_state in ("DONE", "FAILED"):
                break
            time.sleep(2)

        # Fetch results
        results_resp = self.session.get(
            self._url(f"/services/search/jobs/{sid}/results"),
            params={"output_mode": "json", "count": max_results},
        )
        results_resp.raise_for_status()
        return results_resp.json().get("results", [])

    def get_triggered_alerts(self) -> list[dict]:
        """Return all currently triggered (fired) alerts."""
        resp = self.session.get(
            self._url("/services/alerts/fired_alerts"),
            params={"output_mode": "json", "count": 50},
        )
        resp.raise_for_status()
        entries = resp.json().get("entry", [])
        return [
            {
                "name": e["name"],
                "trigger_time": e["content"].get("trigger_time"),
                "severity": e["content"].get("severity"),
                "count": e["content"].get("triggered_count"),
                "savedsearch_name": e["content"].get("savedsearch_name", ""),
            }
            for e in entries
        ]

    def get_index_stats(self) -> list[dict]:
        """Return event counts and sizes per index."""
        resp = self.session.get(
            self._url("/services/data/indexes"),
            params={"output_mode": "json", "count": 50},
        )
        resp.raise_for_status()
        return [
            {
                "name": e["name"],
                "total_event_count": e["content"].get("totalEventCount"),
                "current_size_mb": e["content"].get("currentDBSizeMB"),
                "min_time": e["content"].get("minTime"),
                "max_time": e["content"].get("maxTime"),
            }
            for e in resp.json().get("entry", [])
        ]

    def get_saved_searches(self) -> list[dict]:
        """Return saved searches (alerts and reports)."""
        resp = self.session.get(
            self._url("/services/saved/searches"),
            params={"output_mode": "json", "count": 50},
        )
        resp.raise_for_status()
        return [
            {
                "name": e["name"],
                "search": e["content"].get("search", ""),
                "cron_schedule": e["content"].get("cron_schedule", ""),
                "is_scheduled": e["content"].get("is_scheduled", False),
                "alert_type": e["content"].get("alert_type", ""),
            }
            for e in resp.json().get("entry", [])
        ]

    def ping(self) -> bool:
        """Check Splunk connectivity."""
        try:
            resp = self.session.get(
                self._url("/services/server/info"),
                params={"output_mode": "json"},
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False
