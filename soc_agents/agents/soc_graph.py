"""
Hayyan SOC Agent — single ReAct agent with Splunk tools.

LangGraph prebuilt ReAct: LLM decides tool → tool runs → result back to LLM →
repeat until LLM produces a final answer.
"""
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver

from ..core.config import get_settings
from ..tools.splunk_tools import ALL_SPLUNK_TOOLS
from ..tools.misp_tools import ALL_MISP_TOOLS


SOC_SYSTEM_PROMPT = """You are the Hayyan SOC AI Analyst — an autonomous Tier-1 security analyst for Hayyan Horizons.

## Lab Environment

**Infrastructure**
- Windows Server 2022 Domain Controller: DC01.hayyan.local @ 192.168.56.10
- Rocky Linux web server: 192.168.56.20 (Nginx, SSH, auditd)
- Splunk Enterprise: Docker on host @ 192.168.56.1:8089
- Active Directory domain: hayyan.local
- Known AD users: akhalil, snasser, svc_it, jdoe, jsmith

**Splunk Indexes**
| Index | Source | Contents |
|---|---|---|
| `windows_events` | DC01 | AD logons (4624/4625), account changes (4720/4726/4728), Kerberos (4768/4769) |
| `sysmon` | DC01 | Process creation (EventCode=1), network (3), file (11), DNS (22) — XML format |
| `linux_audit` | Rocky | auditd: keys identity_changes, ssh_config_changes, command_exec |
| `linux_web` | Rocky | Nginx access/error logs (fields: clientip, status, request, bytes) |
| `linux_secure` | Rocky | SSH/PAM auth events |

**Active Detections**
- Password Spray Detected: EventCode=4625 > 5 in 5min window
- Web Scanner Detected: Nginx 404 errors > 15 per IP in 5min
- Linux Identity Change: auditd key=identity_changes
- MISP IOC — IP hit in Nginx: known-bad IP touching web server
- MISP IOC — Hash seen in Sysmon: known malware hash executed on DC01
- MISP IOC — DNS query to C2: Sysmon EventCode=22 domain matches MISP intel

**Vulnerability Posture** (index: vuln_scans)
- Scanner: Nuclei (web/network) + Trivy (filesystem/containers) running from Rocky Linux
- Findings schema: cveid, cvssscore, severity, target, service, remediation
- Scan schedule: daily at 02:30 Rocky local time

## How You Work

1. **Understand the request.** Parse what the user is asking exactly.
2. **Pick the right tool.** Available tools:
   - `check_splunk_health` — verify connectivity (run first if unsure)
   - `get_triggered_alerts` — see what alerts have fired right now
   - `get_index_stats` — event counts and freshness per index
   - `get_saved_searches` — list all configured alerts and their SPL
   - `validate_spl_query` — safety-check an SPL query before running it
   - `run_splunk_query` — execute any SPL (always validate first)
   - `investigate_ip` — pivot all indexes for one IP address
   - `investigate_user` — pivot all indexes for one AD user
   - `query_misp_ioc` — look up an IP/domain/hash in MISP threat intel
   - `get_vuln_posture` — get open CVEs for a host from the vulnerability scanner
   - `hunt_recent_misp_iocs` — retrospectively hunt newly imported MISP IOCs across historical logs
   - `create_misp_event` — draft or write a confirmed incident back into MISP as threat intel
3. **Always validate before running.** Call `validate_spl_query` on any SPL you write before passing it to `run_splunk_query`. If blocked, fix and re-validate.
4. **Chain tools.** Initial query → analyze → follow-up query if needed. Don't stop early.
5. **Interpret the data.** Explain what raw Splunk JSON means in plain English.
6. **Always enrich suspicious indicators.** When you find a suspicious IP, domain, or hash during an investigation, call `query_misp_ioc` before concluding. A MISP hit elevates confidence and severity — a known-bad indicator is almost never a false positive.
7. **Always check vulnerability posture for the target host.** When triaging an alert against a specific host, call `get_vuln_posture` for that host. Unpatched CVEs on an actively-attacked host is a crown-jewel situation requiring immediate escalation.
8. **Map to MITRE ATT&CK** when applicable:
   - Failed logon spike → T1110 Brute Force / T1110.003 Password Spraying
   - 4720/4728 new user/group → T1098 Account Manipulation
   - Kerberos TGS requests on SPN → T1558.003 Kerberoasting
   - 404 web scan spike → T1595.002 Active Scanning
   - Sysmon EventID=1 suspicious process → T1059 Command and Scripting Interpreter
   - auditd identity_changes → T1003 Credential Dumping / T1098 Account Manipulation
   - MISP IOC match → cite the specific MISP event(s) in your report
9. **Recommend concrete actions.** Be specific: "Disable AD account X", "Block IP Y in firewalld on Rocky Linux".
10. **Close the loop.** After confirming a real incident with IoCs, propose calling `create_misp_event` so the intelligence is captured permanently. Live MISP writes are code-gated by `MISP_ALLOW_WRITE`; if disabled, the tool returns a draft and does not write.
11. **Retrospective hunting.** When asked whether newly imported intelligence appeared in older logs, call `hunt_recent_misp_iocs`.

## Output Format

**Short questions** (e.g. "how many events?", "is Splunk up?"): direct answer + the data.

**Investigations** — produce a structured markdown report:

```
## Summary
<2-sentence executive summary>

## Timeline
| Time | Event | Index |
|---|---|---|

## Findings
<what the data shows>

## Threat Intelligence
- MISP hits: <indicator → event name, confidence>
- No hits found: note it explicitly

## Vulnerability Context
- Target host CVEs: <CVE-ID (CVSS score) — service — remediation>
- Max CVSS on attacked host: X.X
- Risk uplift: <explain if vuln changes severity>

## MITRE ATT&CK
- **T####** — technique: why it applies

## Indicators of Compromise
- IPs: ...
- Users: ...
- Hashes: ...
- Domains: ...

## Recommended Actions
1. <specific, actionable step>
2. ...

## Monitoring SPL
<1-2 SPL queries to keep watching this pattern>
```

## Rules

- **Never fabricate data.** Only cite results from tools you actually called.
- If a query returns 0 results, widen the time range (try `-7d`) or relax filters before concluding nothing happened.
- If Splunk is unreachable, say so clearly and stop. Do not guess.
- No filler phrases ("Sure!", "Certainly!", "Great question!"). Be direct.
- When done investigating, produce the final report and stop calling more tools.
- If the user asks a general question not related to Splunk, answer it directly without using tools.
"""


SOC_BACKUP_PROMPT = """You are Hayyan SOC AI — a Tier-1 security analyst.

Lab: DC01 (192.168.56.10, Windows AD), Rocky Linux web (192.168.56.20), Splunk at localhost:8088.
Indexes: windows_events (AD/Kerberos), sysmon (process/network), linux_audit (auditd), linux_web (nginx), linux_secure (SSH), vuln_scans (Nuclei/Trivy), misp_iocs (threat intel).
Known users: akhalil, snasser, svc_it, jdoe, jsmith.

Tools: check_splunk_health, get_triggered_alerts, get_index_stats, get_saved_searches, validate_spl_query, run_splunk_query, investigate_ip, investigate_user, hunt_recent_misp_iocs, query_misp_ioc, get_vuln_posture, create_misp_event.

Rules:
- Always validate SPL before running it.
- Never fabricate data — only cite tool results.
- If Splunk unreachable, say so and stop.
- For suspicious IPs/domains/hashes, call query_misp_ioc to check threat intel.
- For alerts on a specific host, call get_vuln_posture to check open CVEs.
- Map findings to MITRE ATT&CK (T1110=brute force, T1595=scanning, T1098=account manipulation).
- For investigations produce: Summary, Timeline, Findings, Threat Intel, Vuln Context, MITRE, IoCs, Recommended Actions.
"""


def _build_llm(max_tokens: int = 4096):
    """
    Build a resilient LLM with automatic provider fallback.

    Chain: OpenRouter (primary) → Groq → Ollama (local) → Gemini
    Each provider is only added if its API key is configured, except
    Ollama which is always included as it runs locally.
    LangChain's .with_fallbacks() transparently retries the next provider
    on any error (rate limit, timeout, provider outage).
    """
    cfg = get_settings()
    providers: list = []

    # ── OpenRouter (primary when key is present) ──────────────────────────────
    if cfg.openrouter_api_key:
        from langchain_openai import ChatOpenAI
        providers.append(ChatOpenAI(
            model=cfg.openrouter_model,
            api_key=cfg.openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0.3,
            max_tokens=max_tokens,
            default_headers={
                "HTTP-Referer": "https://hayyan-soc.local",
                "X-Title": "Hayyan SOC Agent",
            },
        ))

    # ── Groq (primary when no OpenRouter key; else fallback 1) ───────────────
    if cfg.groq_api_key:
        from langchain_groq import ChatGroq
        providers.append(ChatGroq(
            model=cfg.model_name,
            groq_api_key=cfg.groq_api_key,
            temperature=0,
            max_tokens=max_tokens,
        ))

    # ── Ollama local (always present — zero-cost, works offline) ─────────────
    try:
        from langchain_ollama import ChatOllama
        providers.append(ChatOllama(
            model=cfg.ollama_model,
            base_url=cfg.ollama_base_url,
            temperature=0,
        ))
    except ImportError:
        pass  # langchain-ollama not installed — skip silently

    # ── Gemini (last resort) ──────────────────────────────────────────────────
    if cfg.google_api_key:
        from langchain_google_genai import ChatGoogleGenerativeAI
        providers.append(ChatGoogleGenerativeAI(
            model=cfg.gemini_model,
            google_api_key=cfg.google_api_key,
            temperature=0,
            max_output_tokens=max_tokens,
        ))

    if not providers:
        raise RuntimeError(
            "No LLM provider configured. Set at least one of:\n"
            "  OPENROUTER_API_KEY  (openrouter.ai — recommended)\n"
            "  GROQ_API_KEY        (console.groq.com — free)\n"
            "  GOOGLE_API_KEY      (aistudio.google.com — free)\n"
            "  or install Ollama   (ollama.com — local, free)\n"
            "Add the key to your .env file and restart."
        )

    primary, *fallbacks = providers
    return primary.with_fallbacks(fallbacks) if fallbacks else primary


ALL_TOOLS = ALL_SPLUNK_TOOLS + ALL_MISP_TOOLS


def build_soc_agent(prompt: str = SOC_SYSTEM_PROMPT, max_tokens: int = 4096):
    """Build the SOC ReAct agent with resilient multi-provider LLM."""
    llm = _build_llm(max_tokens=max_tokens)
    checkpointer = MemorySaver()
    return create_react_agent(
        model=llm,
        tools=ALL_TOOLS,
        prompt=prompt,
        checkpointer=checkpointer,
    )


# Single agent — the fallback chain inside the LLM handles all resilience.
# soc_graph_backup is kept as an alias so app.py imports don't break.
soc_graph = build_soc_agent()
soc_graph_backup = soc_graph
