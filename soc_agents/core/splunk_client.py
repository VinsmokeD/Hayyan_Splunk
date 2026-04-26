"""
Splunk REST client with auto-scheme detection.

Port 8089 is Splunk's management API. It serves HTTPS by default in standard
installs, but some Docker/dev setups expose it as plain HTTP. This client
auto-detects which scheme works and caches the result for the session.
"""
import json
import logging
import time
import urllib3
import requests
from requests.exceptions import SSLError, ConnectionError as ReqConnErr

from .config import get_settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class SplunkConnectionError(RuntimeError):
    pass


class SplunkClient:
    """Thin REST client for Splunk management API (port 8089).

    Auto-detects HTTP vs HTTPS so the SPLUNK_SCHEME env var is used as a
    *preference*, not a hard requirement. Falls back to the other scheme if
    the preferred one fails with an SSL error.
    """

    def __init__(self):
        cfg = get_settings()
        self._host = cfg.splunk_host
        self._port = cfg.splunk_port
        self._preferred_scheme = cfg.splunk_scheme.lower()
        self._verify = cfg.splunk_verify_ssl

        self.session = requests.Session()
        self.session.auth = (cfg.splunk_username, cfg.splunk_password)
        self.session.verify = False          # always disable cert verification for self-signed

        # Resolved at first use
        self._scheme: str | None = None
        self._base_url: str | None = None

    # ── Scheme auto-detection ─────────────────────────────────────────────────

    def _resolve_scheme(self) -> str:
        """Try preferred scheme first; fall back to the other on SSL errors."""
        schemes = (
            [self._preferred_scheme, "http" if self._preferred_scheme == "https" else "https"]
        )
        last_err: Exception | None = None
        for scheme in schemes:
            url = f"{scheme}://{self._host}:{self._port}/services/server/info"
            try:
                r = self.session.get(url, params={"output_mode": "json"}, timeout=6)
                # Any HTTP response (even 401) means the port is live on this scheme
                log.info("Splunk reachable via %s (HTTP %s)", url, r.status_code)
                return scheme
            except SSLError as e:
                log.warning("Scheme %s failed with SSL error, trying other: %s", scheme, e)
                last_err = e
            except ReqConnErr as e:
                log.warning("Scheme %s connection refused: %s", scheme, e)
                last_err = e
            except Exception as e:
                log.warning("Scheme %s unexpected error: %s", scheme, e)
                last_err = e
        raise SplunkConnectionError(
            f"Cannot reach Splunk at {self._host}:{self._port} with either http or https. "
            f"Last error: {last_err}"
        )

    def _ensure_url(self) -> str:
        if self._base_url is None:
            self._scheme = self._resolve_scheme()
            self._base_url = f"{self._scheme}://{self._host}:{self._port}"
            log.info("Splunk base URL resolved to: %s", self._base_url)
        return self._base_url

    def _url(self, path: str) -> str:
        return f"{self._ensure_url()}{path}"

    # ── Public API ────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Check Splunk connectivity. Returns True if reachable."""
        try:
            self._ensure_url()
            resp = self.session.get(
                self._url("/services/server/info"),
                params={"output_mode": "json"},
                timeout=6,
            )
            return resp.status_code < 500
        except Exception as e:
            log.debug("Splunk ping failed: %s", e)
            return False

    def run_search(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_results: int = 100,
    ) -> list[dict]:
        """Execute a blocking SPL search and return results as list of dicts."""
        search_str = spl if spl.strip().lower().startswith("search") else f"search {spl}"

        # Create search job
        resp = self.session.post(
            self._url("/services/search/jobs"),
            data={
                "search": search_str,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        sid = resp.json()["sid"]

        # Poll until done (max 120 s)
        for _ in range(60):
            status_resp = self.session.get(
                self._url(f"/services/search/jobs/{sid}"),
                params={"output_mode": "json"},
                timeout=15,
            )
            status_resp.raise_for_status()
            state = status_resp.json()["entry"][0]["content"]["dispatchState"]
            if state in ("DONE", "FAILED"):
                break
            time.sleep(2)

        # Fetch results
        results_resp = self.session.get(
            self._url(f"/services/search/jobs/{sid}/results"),
            params={"output_mode": "json", "count": max_results},
            timeout=30,
        )
        results_resp.raise_for_status()
        return results_resp.json().get("results", [])

    def get_triggered_alerts(self) -> list[dict]:
        """Return all currently triggered (fired) alerts, enriched with severity from saved searches."""
        # Fetch fired alerts
        resp = self.session.get(
            self._url("/services/alerts/fired_alerts"),
            params={"output_mode": "json", "count": 50},
            timeout=15,
        )
        resp.raise_for_status()
        entries = resp.json().get("entry", [])

        # Build severity map from saved searches (1=info,2=low,3=medium,4=high,5=critical)
        _sev_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
        sev_by_name: dict[str, str] = {}
        try:
            sr = self.session.get(
                self._url("/services/saved/searches"),
                params={"output_mode": "json", "count": 50},
                timeout=10,
            )
            if sr.status_code == 200:
                for e in sr.json().get("entry", []):
                    sev_num = e["content"].get("alert.severity")
                    if sev_num is not None:
                        sev_by_name[e["name"]] = _sev_map.get(int(sev_num), "medium")
        except Exception:
            pass

        results = []
        for e in entries:
            name = e.get("name", "")
            if not name or name == "-":
                continue
            count = e["content"].get("triggered_alert_count") or e["content"].get("triggered_count")
            results.append({
                "name": name,
                "trigger_time": e["content"].get("trigger_time"),
                "severity": sev_by_name.get(name, "medium"),
                "count": int(count) if count else None,
                "savedsearch_name": name,
            })
        return results

    def get_index_stats(self) -> list[dict]:
        """Return event counts and sizes per index."""
        resp = self.session.get(
            self._url("/services/data/indexes"),
            params={"output_mode": "json", "count": 50},
            timeout=15,
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
            timeout=15,
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
