# Hayyan Horizons SOC Lab — Claude Code Context

## Project Overview
A full Splunk SIEM home lab built on a single Windows 11 laptop (16GB RAM) using VMware Workstation.
Built by Mahmoud, SOC Intern at Hayyan Horizons.

---

## Infrastructure

| Component | Details |
|---|---|
| **Host OS** | Windows 11 (16GB RAM) |
| **Hypervisor** | VMware Workstation |
| **Network** | VMnet2 host-only: `192.168.56.0/24` |
| **Splunk Enterprise** | Docker on host, UI port `8080`, indexer `9997` |
| **Rocky Linux 10 VM** | `192.168.56.20` (also NAT: `192.168.229.100` via ens160) |
| **Windows Server 2022** | `192.168.56.10` — DC01.hayyan.local |
| **Splunk Password** | Hayyan@2024! |

---

## Active Directory

- **Domain:** `hayyan.local` | NetBIOS: `HAYYAN`
- **DC:** `DC01.hayyan.local` at `192.168.56.10`
- **Domain Mode:** Windows2016Domain
- **OUs:** `SOC_Team`, `Hayyan_Staff`
- **Groups:** `SOC_Admins`
- **Users:** `akhalil`, `snasser`, `svc_it`, `jdoe`, `jsmith`
- **SPN (Kerberoasting target):** `HTTP/webserver.hayyan.local` on `svc_it`

---

## Splunk Indexes

| Index | Source | Events |
|---|---|---|
| `linux_audit` | auditd kernel events | ~12,863 |
| `linux_web` | Nginx access/error logs | — |
| `linux_secure` | SSH/PAM auth | — |
| `windows_events` | AD Security/System/Application | — |
| `sysmon` | Sysmon ETW XML (DC01) | — |
| **Total** | | **27,341+** |

---

## Splunk Forwarders

### Rocky Linux UF
- Version: `10.2.2` | Path: `/opt/splunkforwarder`
- Service: `SplunkForwarder`
- Forwards to: `192.168.56.1:9997`
- Monitors: nginx logs, `/var/log/secure`, auditd logs

### Windows UF (DC01)
- Version: `10.2.2` | Path: `C:\Program Files\SplunkUniversalForwarder`
- Runs as: `LocalSystem` (required for Sysmon channel access)
- Monitors: Security, System, Application, Sysmon channels (`renderXml=true`)

---

## Rocky Linux Hardening

- **SELinux:** Enforcing — nginx logs keep `httpd_log_t`, splunkfwd access via `setfacl`
- **Firewalld:** Drop zone (stealthy — no ping response)
- **SSH:** `PermitRootLogin no`, `MaxAuthTries 3`, `AllowTcpForwarding no`, `X11Forwarding no`
- **Fail2Ban:** `maxretry=3`, `bantime=1h`
- **auditd rules:** `identity_changes`, `ssh_config_changes`, `webserver_logs`, `command_exec`

---

## Sysmon (DC01)

- Version: `v15.20` | Config: SwiftOnSecurity
- Log channel: `Microsoft-Windows-Sysmon/Operational`
- Format in Splunk: XML — use this rex for CommandLine:
  ```spl
  rex field=_raw "Name='CommandLine'>(?<cmd>[^<]+)"
  ```

---

## Configured Splunk Alerts

| Alert | Schedule | Trigger | Severity |
|---|---|---|---|
| Password Spray Detected | `*/5 * * * *` | EventCode=4625, count > 5 | High |
| Web Scanner Detected | `*/5 * * * *` | Nginx 404s > 15 per IP | High |
| Linux Identity Change | `*/10 * * * *` | auditd key=identity_changes | Medium |

All alerts use **Add to Triggered Alerts** with throttle enabled.

---

## Attack Scenarios Verified

| Attack | Method | Detection |
|---|---|---|
| Web Scanner | 192.168.56.10 → .20, 1223 hits | Nginx 404 spike alert |
| Password Spray | 6 AD accounts hit | Event 4625, count > 5 |
| Linux Identity Change | `touch /etc/passwd` | auditd identity_changes key |
| SSH Brute Force | 15 failed auth events | linux_secure index |
| AD Recon | User/group creation | Events 4720/4728/4769 |
| Post-Exploitation | Process creation | Sysmon Event ID 1 |

---

## Known Issues & Fixes

| Issue | Fix |
|---|---|
| auditd can't be restarted manually | Use `augenrules --load` instead |
| auditd future timestamps (year 2038) | Cosmetic — fix with `timedatectl` / `chronyc` |
| nginx SELinux relabeling breaks things | Use `setfacl` for splunkfwd access, don't relabel |
| Docker volume mounts break Splunk perms | Run Splunk container without volume mounts |
| Port 8000 taken by Docker Desktop | Map `8080:8000` in Docker run command |
| Sysmon errorCode=5 in UF logs | Run SplunkForwarder as LocalSystem |

---

## Planned Next Steps

- [ ] Complete Phase 2 documentation (MD file with auditd, Fail2Ban, SSH, AD, alerts)
- [ ] Deploy vulnerable web apps (command injection, XSS)
- [ ] CIM field mapping for Splunk
- [ ] Splunk Add-on for Sysmon (auto field extraction)
- [ ] Simulate Kerberoasting against `svc_it` SPN
- [ ] Join Rocky Linux to `hayyan.local` domain
