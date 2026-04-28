# Post-Troubleshooting API Key Rotation Step

Use this immediately after troubleshooting to rotate MISP API credentials and reduce exposure.

## Scope

- Rotate MISP API key used by local automation.
- Update .env.
- Validate sync still works.

## Step-by-Step

1. Generate a new key in MISP UI
- Open: https://127.0.0.1:8443
- Login: admin@admin.test / MispAdmin2026!
- Go to: Administration -> List Auth Keys -> Add authentication key
- Use description: post-troubleshooting-rotation
- Copy the key once

2. Replace the old key in .env
- Set MISP_API_KEY=<new_key>
- Keep MISP_URL=https://127.0.0.1:8443

3. Invalidate old key
- In the same Auth Keys page, disable or delete the previous key.

4. Validate immediately
```powershell
python scripts/misp_sync_splunk.py --dry-run
python scripts/misp_sync_splunk.py
```

5. Confirm lookup visibility
```powershell
python -c "import requests,urllib3; urllib3.disable_warnings(); d={'search':'| inputlookup misp_ioc_lookup.csv | head 3','output_mode':'json','exec_mode':'oneshot'}; r=requests.post('https://localhost:8088/services/search/jobs',auth=('admin','Hayyan@2024!'),verify=False,data=d,timeout=30); print(r.status_code); print(r.text[:600])"
```

## Rotation Completion Criteria

- New key works for sync.
- Old key no longer valid.
- .env contains only current active key.
