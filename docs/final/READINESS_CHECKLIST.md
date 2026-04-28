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
- [ ] PASS/FAIL: ROCKY_HOST, ROCKY_USER, ROCKY_PASSWORD, and ROCKY_SCAN_DIR are set.

## C. Splunk Validation

- [ ] PASS/FAIL: python scripts/validate_splunk.py completes without failures.
- [ ] PASS/FAIL: Indexes exist: vuln_scans, misp_iocs, ai_soc_audit.
- [ ] PASS/FAIL: HEC test ingestion succeeds for all three indexes.

## D. IOC Pipeline

- [x] PASS: python scripts/misp_sync_splunk.py --dry-run returns 4,995 unique IOC rows.
- [x] PASS: python scripts/misp_sync_splunk.py writes data/misp_ioc_lookup.csv.
- [x] PASS: Splunk search `| inputlookup misp_ioc_lookup.csv | stats count by ioc_type` returns data.
- [x] PASS: Large lookup refresh works through chunked outputlookup fallback.

## E. Rocky Scanner Pipeline

- [x] PASS: python scripts/deploy_rocky.py deploys the scanner pack without hardcoded credentials and verifies Nuclei/Trivy.
- [x] PASS: python scripts/test_scanners.py runs /opt/hayyan-scan/orchestrator.sh successfully.
- [x] PASS: Splunk search `index=vuln_scans scanid="run-20260428-171022" | stats count by scanner, severity` returns 46 normalized Trivy findings.
- [x] PASS: Scanner-side MISP mirroring respects MISP_ALLOW_WRITE=false.

## F. AI Agent Operational Loop

- [x] PASS: API health endpoint is live at http://localhost:8500/api/health.
- [x] PASS: API MISP health endpoint confirms MISP connectivity.
- [x] PASS: API vulnerability posture endpoint returns Rocky exposure context.
- [ ] PASS/FAIL: AI agent can call check_splunk_health.
- [ ] PASS/FAIL: AI agent can call get_vuln_posture for Rocky or DC01.
- [ ] PASS/FAIL: AI agent can call hunt_recent_misp_iocs.
- [ ] PASS/FAIL: Splunk search `index=ai_soc_audit | stats count by tool_name, status` shows tool-call audit events.
- [ ] PASS/FAIL: create_misp_event returns a draft while MISP_ALLOW_WRITE=false.
- [ ] PENDING APPROVAL: `/api/chat` with external LLM provider for "Investigate 192.168.56.20 using MISP and vulnerability context".

## G. Dashboard and Detections

- [ ] PASS/FAIL: HayyanSOC dashboard loads at /en-US/app/HayyanSOC/threat_dashboard.
- [ ] PASS/FAIL: Risk-adjusted detections are present and use inputlookup where applicable.

## H. Post-Troubleshooting Security Hygiene

- [ ] PASS/FAIL: MISP API key rotated after troubleshooting.
- [ ] PASS/FAIL: Previous API key is disabled/deleted.
- [ ] PASS/FAIL: No stale login hints remain in operator docs.

## Final Gate

- READY FOR DEMO if all critical sections A-E are PASS and section F is PASS except the external LLM chat item, which requires explicit approval to send lab context to the configured provider.
