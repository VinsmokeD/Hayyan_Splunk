"""
Hayyan SOC Dashboard - Streamlit UI for monitoring and approval workflow.
Run with: streamlit run soc_agents/ui/streamlit_app.py
"""
import streamlit as st
import requests
import json
from datetime import datetime
import asyncio

st.set_page_config(
    page_title="Hayyan SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main { padding: 0 2rem; }
    .metric { background: #1e293b; padding: 1rem; border-radius: 8px; border-left: 4px solid #3b82f6; }
    </style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:8500"

def get_health():
    try:
        resp = requests.get(f"{API_URL}/api/health", timeout=5)
        return resp.json()
    except Exception as e:
        return {"status": "error", "error": str(e)}

def get_alerts():
    try:
        resp = requests.get(f"{API_URL}/api/alerts", timeout=10)
        return resp.json().get("alerts", [])
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        return []

def get_indexes():
    try:
        resp = requests.get(f"{API_URL}/api/indexes", timeout=10)
        return resp.json().get("indexes", [])
    except Exception as e:
        st.error(f"Failed to fetch indexes: {e}")
        return []

# Header
st.title("🛡️ Hayyan SOC Operations Center")
st.markdown("**Autonomous AI Tier-1 Analyst** | Powered by Gemini & LangGraph")

# Health Check
col1, col2, col3 = st.columns(3)
health = get_health()
with col1:
    status_color = "🟢" if health.get("status") == "ok" else "🔴"
    st.metric("API Status", status_color + " " + health.get("status", "unknown").upper())
    
with col2:
    splunk_status = "Connected" if "connected" in health.get("splunk", "").lower() else "Disconnected"
    st.metric("Splunk", splunk_status)
    
with col3:
    st.metric("Model", health.get("model", "unknown"))

st.divider()

# Main Dashboard
tab1, tab2, tab3, tab4 = st.tabs(["Active Alerts", "Index Stats", "Investigation Chat", "System Logs"])

with tab1:
    st.subheader("Triggered Alerts")
    alerts = get_alerts()
    if alerts:
        for alert in alerts:
            with st.container():
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.write(f"**{alert.get('name', 'Unknown')}**")
                with col2:
                    severity = alert.get('severity', 'unknown').upper()
                    st.write(f"`{severity}`")
                with col3:
                    if st.button("Investigate", key=alert.get('name')):
                        st.session_state.selected_alert = alert.get('name')
                st.caption(f"Triggered: {alert.get('trigger_time', 'unknown')}")
                st.divider()
    else:
        st.info("No active alerts at this time.")

with tab2:
    st.subheader("Splunk Index Statistics")
    indexes = get_indexes()
    if indexes:
        for idx in indexes:
            count = int(idx.get("total_event_count") or 0)
            if count > 0:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.write(f"**{idx['name']}**")
                with col2:
                    st.metric("Events", f"{count:,}")
                with col3:
                    st.metric("Size (MB)", idx.get("current_size_mb", "N/A"))
    else:
        st.info("No indexes available.")

with tab3:
    st.subheader("Send Investigation Request")
    message = st.text_area(
        "Describe what you want to investigate:",
        placeholder="e.g., Investigate IP 192.168.56.20 for suspicious activity in the last 24 hours",
        height=100
    )
    
    if st.button("Submit Investigation", type="primary"):
        if message:
            st.info("Submitting investigation request to agents...")
            try:
                resp = requests.post(
                    f"{API_URL}/api/chat",
                    json={"message": message},
                    timeout=120
                )
                result = resp.json()
                if "report" in result:
                    st.markdown("### Investigation Report")
                    st.markdown(result["report"])
                else:
                    st.error(f"Unexpected response: {result}")
            except Exception as e:
                st.error(f"Investigation failed: {e}")
        else:
            st.warning("Please enter an investigation request.")

with tab4:
    st.subheader("System Logs")
    st.info("Integration with Splunk ai_soc_audit index coming soon.")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    if st.button("🔄 Refresh All", use_container_width=True):
        st.rerun()
    
    st.divider()
    
    st.subheader("Quick Actions")
    
    if st.button("📋 Check Splunk Health", use_container_width=True):
        health = get_health()
        st.json(health)
    
    if st.button("🚀 Rebuild Knowledge Base", use_container_width=True):
        st.info("This would rebuild the ChromaDB knowledge base...")
        
    st.divider()
    
    st.subheader("Documentation")
    st.markdown("""
    - [GitHub Repository](#)
    - [MITRE ATT&CK Framework](#)
    - [Splunk Query Guide](#)
    - [LangGraph Docs](#)
    """)
    
    st.divider()
    
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    pass
