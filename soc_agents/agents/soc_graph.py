"""
Hayyan SOC LangGraph — multi-agent investigation workflow.

Graph topology:
  START → triage → [query_agent | alert_agent | investigation_agent | report_agent] → synthesize → END

The triage node classifies the user request and routes to the most appropriate
specialist. Specialists may loop back to triage to chain sub-tasks. The
synthesize node formats the final actionable report.
"""
from typing import Literal
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from ..core.config import get_settings
from ..core.models import SOCState
from ..tools.splunk_tools import ALL_SPLUNK_TOOLS

_cfg = get_settings()

# ── LLM ─────────────────────────────────────────────────────────────────────

def _llm(*, tools: list | None = None) -> ChatGoogleGenerativeAI:
    llm = ChatGoogleGenerativeAI(
        model=_cfg.model_name,
        google_api_key=_cfg.google_api_key,
        temperature=0,
        max_output_tokens=4096,
    )
    if tools:
        return llm.bind_tools(tools)
    return llm


# ── System Prompts ───────────────────────────────────────────────────────────

_TRIAGE_SYSTEM = """You are the SOC Supervisor for Hayyan Horizons, a cybersecurity operations center.
You oversee a team of specialized AI agents connected to Splunk SIEM.

Environment:
- Splunk indexes: linux_audit, linux_web, linux_secure, windows_events, sysmon
- Active Directory domain: hayyan.local (DC01 @ 192.168.56.10)
- Rocky Linux server @ 192.168.56.20
- Known users: akhalil, snasser, svc_it, jdoe, jsmith
- SPN (Kerberoasting target): HTTP/webserver.hayyan.local on svc_it

Your job: analyze the user's request and decide which specialist to invoke.
Reply ONLY with one of these routing tokens on the last line:
  ROUTE:query_agent
  ROUTE:alert_agent
  ROUTE:investigation_agent
  ROUTE:report_agent

Guidelines:
- "run a search / query / SPL / show me events" → query_agent
- "what alerts are triggered / fired / active" → alert_agent
- "investigate IP / user / incident / attack" → investigation_agent
- "create a report / summarize findings / generate IOC list" → report_agent
- If unsure, choose investigation_agent."""

_QUERY_AGENT_SYSTEM = """You are the Splunk Query Specialist for Hayyan Horizons SOC.
You have expert-level SPL knowledge and direct access to all Splunk indexes.

Available indexes:
- index=windows_events — AD Security/System/Application events (EventCodes: 4624,4625,4634,4648,4672,4720,4728,4769)
- index=sysmon — Sysmon ETW XML (EventCode=1 process, 3 network, 7 image load, 11 file, 22 DNS)
  Extract CommandLine: rex field=_raw "Name='CommandLine'>(?<cmd>[^<]+)"
- index=linux_audit — auditd kernel events (key=identity_changes,ssh_config_changes,command_exec)
- index=linux_web — Nginx access/error logs (fields: clientip, status, request, bytes)
- index=linux_secure — SSH/PAM auth (fields: src, user, action)

Instructions:
1. Use run_splunk_query to execute SPL queries.
2. Always enrich counts with relevant fields (stats count by src_ip, user, EventCode etc).
3. If results are empty try broadening the time range.
4. After gathering data, provide clear analysis with:
   - What was found
   - Anomalies / suspicious patterns
   - Recommended follow-up SPL queries"""

_ALERT_AGENT_SYSTEM = """You are the Alert Triage Specialist for Hayyan Horizons SOC.
Your job is to fetch, triage, and analyze Splunk fired alerts.

Configured alerts and their meaning:
- "Password Spray Detected" → EventCode=4625 > 5 per 5min → credential attack
- "Web Scanner Detected" → Nginx 404s > 15/IP per 5min → reconnaissance
- "Linux Identity Change" → auditd identity_changes key → privilege/persistence

Instructions:
1. Use get_triggered_alerts to fetch active alerts.
2. For each alert, run targeted SPL to get the underlying events.
3. Correlate across indexes if needed (e.g., web scan + subsequent auth attempt).
4. Assign severity: Critical / High / Medium / Low.
5. For each finding provide:
   - MITRE ATT&CK tactic/technique
   - Immediate containment action
   - Investigation next steps"""

_INVESTIGATION_AGENT_SYSTEM = """You are the Threat Investigator for Hayyan Horizons SOC.
You conduct deep-dive investigations using all available Splunk tools.

Attack scenarios in this lab:
- Web Scanner: 192.168.56.10 → .20, Nginx 404 spike
- Password Spray: 6 AD accounts hit, EventCode 4625
- Linux Identity Change: touch /etc/passwd, auditd
- SSH Brute Force: 15 failed auth events, linux_secure
- AD Recon: Events 4720/4728/4769, user/group creation
- Post-Exploitation: Sysmon EventCode=1 process creation
- Kerberoasting: EventCode=4769, SPN HTTP/webserver.hayyan.local, svc_it account

Instructions:
1. Use investigate_ip and investigate_user for targeted investigations.
2. Use run_splunk_query for custom correlation searches.
3. Chain queries — findings from one query should drive the next.
4. Build a timeline of events.
5. Map findings to MITRE ATT&CK framework.
6. Conclude with: confirmed/suspected/false positive, severity, affected assets, IOCs."""

_REPORT_AGENT_SYSTEM = """You are the SOC Report Writer for Hayyan Horizons.
You synthesize investigation findings into professional, actionable reports.

Your reports MUST include:
1. **Executive Summary** (2-3 sentences for management)
2. **Timeline of Events** (chronological table)
3. **Technical Findings** (detailed per-asset analysis)
4. **MITRE ATT&CK Mapping** (tactic + technique ID + description)
5. **Indicators of Compromise (IOCs)** (IPs, hashes, domains, usernames)
6. **Severity Assessment** (Critical/High/Medium/Low with justification)
7. **Immediate Containment Actions** (numbered, specific)
8. **Recommended Long-term Mitigations**
9. **SPL Queries for Ongoing Monitoring**

Format: GitHub-flavored Markdown. Be specific and actionable."""


# ── Nodes ────────────────────────────────────────────────────────────────────

def triage_node(state: SOCState) -> dict:
    """Classify user intent and route to appropriate specialist."""
    llm = _llm()
    messages = [SystemMessage(content=_TRIAGE_SYSTEM)] + state["messages"]
    response = llm.invoke(messages)
    content = response.content

    # Extract routing decision from last line
    next_agent = "investigation_agent"  # safe default
    for line in reversed(content.strip().splitlines()):
        if line.strip().startswith("ROUTE:"):
            next_agent = line.strip().replace("ROUTE:", "").strip()
            break

    return {
        "messages": [response],
        "next_agent": next_agent,
        "current_task": f"Routing to {next_agent}",
    }


def _make_specialist_node(system_prompt: str, agent_name: str):
    """Factory for tool-using specialist nodes."""
    specialist_llm = _llm(tools=ALL_SPLUNK_TOOLS)
    tool_executor = ToolNode(ALL_SPLUNK_TOOLS, handle_tool_errors=True)

    def specialist_node(state: SOCState) -> dict:
        messages = [SystemMessage(content=system_prompt)] + state["messages"]
        response = specialist_llm.invoke(messages)
        updates: dict = {"messages": [response], "current_task": agent_name}

        # If the LLM didn't call any tools, we're done
        if not response.tool_calls:
            return updates

        # Execute all tool calls
        tool_results = tool_executor.invoke({"messages": [response]})
        tool_messages = tool_results.get("messages", [])

        # Collect raw Splunk data for the report agent
        splunk_data = [m.content for m in tool_messages if hasattr(m, "content")]
        updates["messages"] = updates["messages"] + tool_messages
        updates["splunk_results"] = splunk_data

        # Second LLM call to interpret tool results
        followup_messages = [SystemMessage(content=system_prompt)] + state["messages"] + [response] + tool_messages
        followup = specialist_llm.invoke(followup_messages)
        updates["messages"] = updates["messages"] + [followup]

        # If still calling tools, continue looping (handled by edge)
        return updates

    specialist_node.__name__ = agent_name
    return specialist_node


def synthesize_node(state: SOCState) -> dict:
    """Final synthesis: generate the actionable investigation report."""
    llm = _llm()
    context_summary = "\n\n".join([
        m.content for m in state["messages"]
        if isinstance(m, AIMessage) and m.content
    ][-6:])  # last 6 AI messages to stay within context

    synthesis_messages = [
        SystemMessage(content=_REPORT_AGENT_SYSTEM),
        HumanMessage(content=(
            "Based on all findings below, generate a complete SOC investigation report.\n\n"
            f"FINDINGS:\n{context_summary}"
        )),
    ]
    report = llm.invoke(synthesis_messages)
    return {
        "messages": [report],
        "report": report.content,
        "current_task": "complete",
    }


# ── Routing ──────────────────────────────────────────────────────────────────

def route_after_triage(state: SOCState) -> Literal[
    "query_agent", "alert_agent", "investigation_agent", "report_agent"
]:
    return state.get("next_agent", "investigation_agent")


def route_after_specialist(state: SOCState) -> Literal["synthesize", "investigation_agent"]:
    """If the last message still has tool calls pending, stay in the specialist loop."""
    last_msg = state["messages"][-1] if state["messages"] else None
    if last_msg and hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        return "investigation_agent"
    return "synthesize"


# ── Graph Assembly ───────────────────────────────────────────────────────────

def build_soc_graph():
    builder = StateGraph(SOCState)

    # Add nodes
    builder.add_node("triage", triage_node)
    builder.add_node("query_agent", _make_specialist_node(_QUERY_AGENT_SYSTEM, "query_agent"))
    builder.add_node("alert_agent", _make_specialist_node(_ALERT_AGENT_SYSTEM, "alert_agent"))
    builder.add_node("investigation_agent", _make_specialist_node(_INVESTIGATION_AGENT_SYSTEM, "investigation_agent"))
    builder.add_node("report_agent", _make_specialist_node(_REPORT_AGENT_SYSTEM, "report_agent"))
    builder.add_node("synthesize", synthesize_node)

    # Edges
    builder.add_edge(START, "triage")
    builder.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "query_agent": "query_agent",
            "alert_agent": "alert_agent",
            "investigation_agent": "investigation_agent",
            "report_agent": "report_agent",
        },
    )
    for specialist in ("query_agent", "alert_agent", "investigation_agent", "report_agent"):
        builder.add_edge(specialist, "synthesize")

    builder.add_edge("synthesize", END)

    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


# Module-level singleton
soc_graph = build_soc_graph()
