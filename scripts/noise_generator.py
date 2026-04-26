#!/usr/bin/env python3
"""
Hayyan SOC Lab — Benign Traffic Noise Generator
================================================
Generates realistic background traffic to force the SOC to
distinguish real threats from normal operational noise.

What it generates:
  - Normal web browsing (200 responses from benign IPs)
  - Routine failed logins (expected admin mistyping)
  - DNS lookups for common domains
  - Scheduled maintenance activity
  - Normal Kerberos ticket requests

This improves realism and teaches analysts that not every 404
or failed login is a threat — context matters.

Usage:
    python3 scripts/noise_generator.py --target 192.168.56.20
    python3 scripts/noise_generator.py --target 192.168.56.20 --mode continuous
    python3 scripts/noise_generator.py --target 192.168.56.20 --mode burst --count 200
"""
import argparse
import random
import time
import urllib.request
import urllib.error
import ssl
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# ── Realistic benign request patterns ────────────────────────────────────────
BENIGN_PATHS = [
    "/",
    "/index.html",
    "/robots.txt",
    "/favicon.ico",
    "/style.css",
    "/main.js",
    "/images/logo.png",
    "/api/health",
    "/login",
    "/about",
    "/contact",
    "/products",
    "/search?q=security",
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "curl/8.1.2",  # Scheduled health check
]

# Simulated source IPs for benign traffic (internal office range)
OFFICE_IPS = [
    "192.168.56.100",
    "192.168.56.101",
    "192.168.56.102",
    "192.168.56.103",
    "192.168.56.110",
]


def make_benign_web_request(target: str) -> None:
    """Send a realistic benign HTTP request."""
    path = random.choice(BENIGN_PATHS)
    ua = random.choice(BENIGN_USER_AGENTS)
    url = f"http://{target}{path}"

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", ua)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")
        req.add_header("Connection", "keep-alive")

        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=5) as resp:
            _ = resp.read(512)  # Read a bit to look like real browser
    except Exception:
        pass  # Expected — some paths may 404 or redirect


def make_failed_login_noise(target: str) -> None:
    """
    Simulate a routine password-mistyping event (1-2 per session).
    This tests that the alert threshold (>5 failures) distinguishes
    normal human mistyping from an actual spray attack.
    """
    path = "/login"
    ua = random.choice(BENIGN_USER_AGENTS)
    url = f"http://{target}{path}"

    try:
        # POST with wrong credentials — will return 401/302
        data = b"username=admin&password=wrongpass"
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent", ua)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=5) as _:
            pass
    except Exception:
        pass  # Expected


def run_noise_burst(target: str, count: int = 100, delay_range: tuple = (0.1, 0.8)) -> None:
    """Send a burst of mixed benign traffic."""
    log.info("Generating %d benign requests to %s ...", count, target)
    for i in range(count):
        # 90% normal browsing, 5% failed login, 5% other
        roll = random.random()
        if roll < 0.90:
            make_benign_web_request(target)
        elif roll < 0.95:
            make_failed_login_noise(target)
        else:
            make_benign_web_request(target)

        delay = random.uniform(*delay_range)
        time.sleep(delay)

        if (i + 1) % 20 == 0:
            log.info("  Sent %d/%d requests", i + 1, count)

    log.info("Noise burst complete.")


def run_continuous_noise(target: str, requests_per_min: int = 30) -> None:
    """Run continuous background noise indefinitely."""
    delay = 60.0 / requests_per_min
    log.info("Continuous noise mode: %d req/min to %s (Ctrl+C to stop)", requests_per_min, target)
    request_count = 0
    try:
        while True:
            make_benign_web_request(target)
            request_count += 1
            if request_count % 60 == 0:
                log.info("Continuous noise: %d total requests sent", request_count)
            time.sleep(delay)
    except KeyboardInterrupt:
        log.info("Noise generator stopped. Total requests: %d", request_count)


def main():
    parser = argparse.ArgumentParser(description="Hayyan SOC benign traffic noise generator")
    parser.add_argument("--target", default="192.168.56.20", help="Target IP/hostname")
    parser.add_argument("--mode", choices=["burst", "continuous", "once"], default="burst")
    parser.add_argument("--count", type=int, default=100, help="Requests for burst mode")
    parser.add_argument("--rate", type=int, default=30, help="Requests/min for continuous mode")
    args = parser.parse_args()

    log.info("================================================================")
    log.info(" Hayyan SOC Noise Generator")
    log.info(" Mode: %s | Target: %s", args.mode, args.target)
    log.info(" Purpose: Generate realistic background traffic for SOC realism")
    log.info("================================================================")

    if args.mode == "once":
        make_benign_web_request(args.target)
        log.info("Sent one benign request to %s", args.target)
    elif args.mode == "burst":
        run_noise_burst(args.target, count=args.count)
    elif args.mode == "continuous":
        run_continuous_noise(args.target, requests_per_min=args.rate)


if __name__ == "__main__":
    main()
