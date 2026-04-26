import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import os
from pathlib import Path

# ── Configuration & Page Setup ───────────────────────────────────────────────
st.set_page_config(
    page_title="Hayyan SOC — Threat-Informed Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Premium Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #090d12;
    }
    .stApp {
        color: #e2eaf4;
    }
    .css-1d391kg {
        background-color: #0e1520;
    }
    .stMetric {
        background-color: #121c2b;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #1e3050;
    }
    .stMetric:hover {
        border-color: #1d8cf8;
        box-shadow: 0 0 10px rgba(29, 140, 248, 0.2);
    }
    </style>
    """, unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://raw.githubusercontent.com/VinsmokeD/Hayyan_Splunk/master/soc_agents/ui/logo.png", width=100) # Placeholder
    st.title("Hayyan SOC")
    st.markdown("---")
    st.subheader("System Health")
    col1, col2 = st.columns(2)
    with col1:
        st.success("Splunk: OK")
    with col2:
        st.success("MISP: OK")
    
    st.markdown("---")
    st.subheader("Active Scanners")
    st.info("Nuclei: Running")
    st.info("Trivy: Idle")
    
    st.markdown("---")
    if st.button("🔄 Force Refresh"):
        st.rerun()

# ── Header ───────────────────────────────────────────────────────────────────
st.title("🛡️ Threat-Informed Defense Layer")
st.markdown("Commercial-grade monitoring of global threat intel and local exposure.")

# ── Row 1: KPI Metrics ───────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.metric(label="Total IOCs (MISP)", value="12,402", delta="+124 (24h)")
with m2:
    st.metric(label="Critical Vulns Open", value="4", delta="-1 (Fix)", delta_color="normal")
with m3:
    st.metric(label="AI Investigations", value="89", delta="12 (Active)")
with m4:
    st.metric(label="Active Threats", value="1", delta="Rogue Scan", delta_color="inverse")

# ── Row 2: Charts ────────────────────────────────────────────────────────────
c1, c2 = st.columns([2, 1])

with c1:
    st.subheader("📈 Threat Activity Timeline")
    # Mock data for timeline
    df_timeline = pd.DataFrame({
        'Time': [datetime.now() - timedelta(hours=i) for i in range(24)],
        'IOC Hits': [0, 1, 0, 0, 2, 0, 5, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 1],
        'Detections': [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
    })
    fig_timeline = px.line(df_timeline, x='Time', y=['IOC Hits', 'Detections'], 
                           template='plotly_dark', color_discrete_sequence=['#1d8cf8', '#f5365c'])
    fig_timeline.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=300)
    st.plotly_chart(fig_timeline, use_container_width=True)

with c2:
    st.subheader("📊 Vulnerability Exposure")
    df_vuln = pd.DataFrame({
        'Severity': ['Critical', 'High', 'Medium', 'Low'],
        'Count': [4, 12, 45, 89]
    })
    fig_vuln = px.pie(df_vuln, values='Count', names='Severity', 
                      color='Severity', color_discrete_map={'Critical':'#f5365c', 'High':'#fb6340', 'Medium':'#ffd600', 'Low':'#2dce89'},
                      hole=.4, template='plotly_dark')
    fig_vuln.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=300)
    st.plotly_chart(fig_vuln, use_container_width=True)

# ── Row 3: Tables ────────────────────────────────────────────────────────────
t1, t2 = st.columns(2)

with t1:
    st.subheader("🔥 Crown Jewel View (Exposed + Attacked)")
    df_crown = pd.DataFrame({
        'Target Host': ['192.168.56.20 (Rocky)', 'DC01.hayyan.local', '192.168.56.30', 'MISP'],
        'Max CVSS': [9.8, 7.5, 4.3, 0.0],
        'Active Scans': ['Rogue (Unauthorized)', 'Authorized', 'None', 'None'],
        'Risk Level': ['🔴 CRITICAL', '🟠 HIGH', '🟢 LOW', '⚪ CLEAN']
    })
    st.table(df_crown)

with t2:
    st.subheader("🤖 AI Agent Audit Trail")
    df_audit = pd.DataFrame({
        'Thread ID': ['thread_abc123', 'thread_xyz789', 'thread_123456'],
        'Last Tool': ['query_misp_ioc', 'get_vuln_posture', 'run_splunk_query'],
        'Status': ['✅ Success', '✅ Success', '⚠️ Retry (Rate Limit)'],
        'Latency': ['1.2s', '2.5s', '0.8s']
    })
    st.table(df_audit)

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption("Hayyan SOC v3.0 — Threat-Informed AI Defense System. Connected to Splunk Enterprise @ 192.168.56.1")
