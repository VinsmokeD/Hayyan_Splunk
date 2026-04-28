# Final Pass/Fail Readiness Checklist

Mark each item Pass or Fail.

## A. Platform Reachability

- [ ] PASS/FAIL: Splunk container is healthy.
- [ ] PASS/FAIL: MISP, MySQL, and Redis containers are healthy.
- [ ] PASS/FAIL: Splunk UI opens at http://localhost:8080.
- [ ] PASS/FAIL: MISP UI opens at https://127.0.0.1:8443.

## B. Canonical Configuration

- [ ] PASS/FAIL: .env uses MISP_URL=https://127.0.0.1:8443.
- [ ] PASS/FAIL: .env contains a valid MISP_API_KEY.
- [ ] PASS/FAIL: SPLUNK_PORT is 8088.
- [ ] PASS/FAIL: SPLUNK_HEC_URL is http://localhost:8086.

## C. Splunk Validation

- [ ] PASS/FAIL: python scripts/validate_splunk.py completes without failures.
- [ ] PASS/FAIL: Indexes exist: vuln_scans, misp_iocs, ai_soc_audit.
- [ ] PASS/FAIL: HEC test ingestion succeeds for all three indexes.

## D. IOC Pipeline (Lookup-Based)

- [ ] PASS/FAIL: python scripts/misp_sync_splunk.py --dry-run returns IOC rows or expected-empty with explanation.
- [ ] PASS/FAIL: python scripts/misp_sync_splunk.py writes data/misp_ioc_lookup.csv.
- [ ] PASS/FAIL: Splunk search | inputlookup misp_ioc_lookup.csv | head 5 returns data.
- [ ] PASS/FAIL: Saved search definitions are lookup-based (not index=misp_iocs subsearch dependent).

## E. Rocky Scanner Pipeline

- [ ] PASS/FAIL: .env contains ROCKY_HOST, ROCKY_USER, ROCKY_PASSWORD, and ROCKY_SCAN_DIR.
- [x] PASS: python scripts/deploy_rocky.py deploys the scanner pack without hardcoded credentials.
- [x] PASS: python scripts/test_scanners.py runs /opt/hayyan-scan/orchestrator.sh successfully.
- [ ] PASS/FAIL: Splunk search `index=vuln_scans | stats count by scanner, severity` returns normalized findings from a real Rocky scan, not only validation or test events.

## F. AI Agent Operational Loop

- [ ] PASS/FAIL: AI agent can call check_splunk_health.
- [ ] PASS/FAIL: AI agent can call get_vuln_posture for Rocky or DC01.
- [ ] PASS/FAIL: AI agent can call hunt_recent_misp_iocs.
- [ ] PASS/FAIL: Splunk search `index=ai_soc_audit | stats count by tool_name, status` shows tool-call audit events.
- [ ] PASS/FAIL: create_misp_event returns a draft while MISP_ALLOW_WRITE=false.

## G. Dashboard and Detections

- [ ] PASS/FAIL: HayyanSOC dashboard loads at /en-US/app/HayyanSOC/threat_dashboard.
- [ ] PASS/FAIL: Risk-adjusted detections are present and use inputlookup where applicable.

## H. Post-Troubleshooting Security Hygiene

- [ ] PASS/FAIL: MISP API key rotated after troubleshooting.
- [ ] PASS/FAIL: Previous API key is disabled/deleted.
- [ ] PASS/FAIL: No stale login hints remain in operator docs.

## Final Gate

- READY FOR DEMO if all critical sections A-F are PASS and no high-risk hygiene item in H is FAIL.
