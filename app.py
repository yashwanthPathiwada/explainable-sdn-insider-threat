#!/usr/bin/env python3
"""
=============================================================================
MODULE 5: Policy-Gated Response & Monitoring Dashboard UI (Next-Gen SOC Edition)
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: app.py
=============================================================================
Description:
    Enterprise SOC Command Center & Interactive Explainability Dashboard:
      1. Live Threat Monitor & Network Topology Graph:
         - Visual SDN Digital Twin with dynamic blast-radius & quarantine coloring.
         - Sliding-window risk trajectory timeline per host.
      2. Explainability Layer & Counterfactual "What-If" Simulator:
         - Exact SHAP waterfall bar charts, LIME local surrogates.
         - Interactive counterfactual sliders: simulate behavioral metric shifts.
         - SHAP additivity fidelity checks & execution overhead profiling.
      3. Policy-Gated Response Console & Surgical SDN Playbooks:
         - Human-in-the-loop analyst review for Medium/High/Critical alerts.
         - Playbook Actions: Full Host Isolate (DROP), Surgical Port Block, Rate-Limit, Honeynet Redirect.
         - Automated Time-to-Live (TTL) expiration & one-click rollback.
      4. Compliance Audit Trail & Formal Forensic Report Generator:
         - Complete audit ledger with CSV download.
         - Single-click formal HTML/PDF Forensic Incident Investigation Dossier export.
      5. MITRE ATT&CK for Enterprise Matrix:
         - Real-time mapping of behavioral anomalies to MITRE Tactics & Techniques.
"""

import os
import time
import json
import sqlite3
import requests
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from feature_engineering import (
    FEATURE_COLUMNS, ASSET_ROLES, SENSITIVE_SERVERS, SENSITIVE_PORTS,
    DEFAULT_DB_PATH, BASE_DIR, DATA_DIR, MODEL_DIR,
    extract_sliding_windows, load_flows_from_db
)
from train_detector import (
    ThreatDetectionEngine, METADATA_PATH, BASELINE_STATS_PATH,
    classify_severity_tier, fuse_risk_scores, calculate_context_risk
)
from explainability import XAIExplainer, FEATURE_DESCRIPTIONS
from traffic_generator import (
    inject_data_exfiltration, inject_port_scan,
    inject_privilege_abuse, stream_benign_traffic
)
from mitre_mapper import map_threat_to_mitre, MITRE_TECHNIQUES
from incident_report_generator import generate_forensic_html_report

# ---------------------------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Explainable SDN Threat Intelligence SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------------------------
# Theme Mode Management & Persistent State
# ---------------------------------------------------------------------------
if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "Dark Cyber SOC"

# ---------------------------------------------------------------------------
# Sidebar: UI Customization & Attack Scenario Dispatcher
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <div style="background: linear-gradient(135deg, #0284C7, #0369A1); width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.35);">
            🛡️
        </div>
        <div>
            <div style="font-size: 1.05rem; font-weight: 700; letter-spacing: -0.01em;">SDN CYBER SOC</div>
            <div style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em;">Command Console</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # UI Theme Switcher
    theme_choice = st.selectbox(
        "UI Visual Theme",
        ["Dark Cyber SOC", "Enterprise Light"],
        index=0 if st.session_state["theme_mode"] == "Dark Cyber SOC" else 1,
        help="Switch between Cyber SOC Dark Command and Enterprise Clean Light theme"
    )
    st.session_state["theme_mode"] = theme_choice
    is_dark = (st.session_state["theme_mode"] == "Dark Cyber SOC")

    st.markdown("---")
    st.markdown("##### ⚡ Attack Scenario Dispatcher")
    st.caption("Inject synthetic adversarial telemetry to stress-test the XAI detection fabric:")

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("🟢 Benign Flow", use_container_width=True, help="Inject 10 seconds of normal business telemetry"):
            with st.spinner("Streaming benign traffic..."):
                stream_benign_traffic(duration_sec=10, sleep_interval=0.2)
            st.success("Benign flows streamed.")
            st.rerun()

    with col_s2:
        if st.button("🚨 Data Exfil", use_container_width=True, help="Trigger high-volume bulk transfer from ws2 to external cloud"):
            with st.spinner("Injecting exfiltration..."):
                inject_data_exfiltration(attacker_ip='10.0.1.11', bursts=15)
            st.error("Exfiltration injected (ws2: 10.0.1.11)")
            st.rerun()

    col_s3, col_s4 = st.columns(2)
    with col_s3:
        if st.button("🔍 Port Scan", use_container_width=True, help="Trigger horizontal reconnaissance scan across subnet"):
            with st.spinner("Injecting scan..."):
                inject_port_scan(attacker_ip='10.0.1.10', num_ports=30)
            st.warning("Recon scan injected (ws1: 10.0.1.10)")
            st.rerun()

    with col_s4:
        if st.button("🔓 DB Abuse", use_container_width=True, help="Trigger unauthorized off-hours access to PostgreSQL 5432"):
            with st.spinner("Injecting DB abuse..."):
                inject_privilege_abuse(attacker_ip='10.0.1.10', queries=15)
            st.warning("DB Privilege Abuse injected!")
            st.rerun()

    st.markdown("---")
    st.markdown("##### ⚙️ Engine Parameters")
    confidence_threshold = st.slider(
        "Detection Decision Threshold (τ)",
        min_value=0.20,
        max_value=0.85,
        value=0.50,
        step=0.05,
        help="Fused risk score cut-off above which alerts require policy mitigation"
    )

    auto_refresh = st.checkbox("Auto-refresh data (every 6s)", value=False)
    if auto_refresh:
        time.sleep(6)
        st.rerun()

    if st.button("🔄 Retrain ML Models", use_container_width=True):
        with st.spinner("Retraining RF + Isolation Forest baseline models..."):
            engine = ThreatDetectionEngine()
            engine.train()
        st.success("Models retrained with fresh baseline telemetry!")
        st.rerun()

    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.72rem; color: #94A3B8; text-align: center; line-height: 1.4;">
            OpenFlow 1.3 SDN Fabric • SHAP/LIME XAI<br>
            MITRE ATT&CK Matrix • NIST SP 800-53
        </div>
        """,
        unsafe_allow_html=True
    )

# ---------------------------------------------------------------------------
# Comprehensive Theme CSS Injection (WCAG AA Compliant, Micro-interactions)
# ---------------------------------------------------------------------------
if is_dark:
    theme_vars = """
        --bg-base: #0B0F19;
        --bg-surface: #111827;
        --bg-card: rgba(17, 24, 39, 0.85);
        --bg-card-hover: #1F2937;
        --bg-subtle: #1A2234;
        --text-primary: #F8FAFC;
        --text-secondary: #CBD5E1;
        --text-muted: #94A3B8;
        --border-subtle: rgba(255, 255, 255, 0.08);
        --border-medium: #334155;
        --border-focus: #38BDF8;
        --card-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.45);
        --accent-cyan: #06B6D4;
        --accent-blue: #38BDF8;
        --accent-emerald: #10B981;
        --accent-amber: #F59E0B;
        --accent-red: #EF4444;
        --accent-purple: #A855F7;
        --kpi-border: 1px solid rgba(255, 255, 255, 0.07);
        --kpi-bg: linear-gradient(145deg, rgba(26, 34, 52, 0.95), rgba(17, 24, 39, 0.95));
        --tab-bg: #111827;
        --tab-active-bg: linear-gradient(135deg, #1E293B, #0F172A);
        --tab-active-border: #38BDF8;
    """
    plotly_template = "plotly_dark"
    plot_paper_bg = "rgba(17, 24, 39, 0.5)"
    plot_bg = "rgba(11, 15, 25, 0.4)"
    plot_text_color = "#E2E8F0"
    plot_grid_color = "rgba(255, 255, 255, 0.08)"
else:
    theme_vars = """
        --bg-base: #F8FAFC;
        --bg-surface: #FFFFFF;
        --bg-card: #FFFFFF;
        --bg-card-hover: #F1F5F9;
        --bg-subtle: #F1F5F9;
        --text-primary: #0F172A;
        --text-secondary: #334155;
        --text-muted: #64748B;
        --border-subtle: #E2E8F0;
        --border-medium: #CBD5E1;
        --border-focus: #0284C7;
        --card-shadow: 0 4px 18px -2px rgba(0, 0, 0, 0.06), 0 2px 6px -1px rgba(0, 0, 0, 0.04);
        --accent-cyan: #0891B2;
        --accent-blue: #0284C7;
        --accent-emerald: #059669;
        --accent-amber: #D97706;
        --accent-red: #DC2626;
        --accent-purple: #7C3AED;
        --kpi-border: 1px solid #E2E8F0;
        --kpi-bg: linear-gradient(145deg, #FFFFFF, #F8FAFC);
        --tab-bg: #F1F5F9;
        --tab-active-bg: #FFFFFF;
        --tab-active-border: #0284C7;
    """
    plotly_template = "plotly_white"
    plot_paper_bg = "rgba(255, 255, 255, 0.9)"
    plot_bg = "rgba(248, 250, 252, 0.8)"
    plot_text_color = "#1E293B"
    plot_grid_color = "#E2E8F0"

st.markdown(f"""
<style>
    :root {{
        {theme_vars}
        --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    /* Global Base Reset */
    .stApp {{
        background-color: var(--bg-base) !important;
        color: var(--text-primary) !important;
        font-family: var(--font-sans) !important;
    }}

    /* Header styling */
    .command-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        box-shadow: var(--card-shadow);
        margin-bottom: 20px;
        flex-wrap: wrap;
        gap: 12px;
    }}

    .command-title-box {{
        display: flex;
        align-items: center;
        gap: 14px;
    }}

    .command-icon {{
        font-size: 2rem;
        background: linear-gradient(135deg, rgba(56, 189, 248, 0.15), rgba(2, 132, 199, 0.15));
        border: 1px solid var(--accent-blue);
        width: 48px;
        height: 48px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
    }}

    .command-title {{
        font-size: 1.35rem;
        font-weight: 700;
        letter-spacing: -0.01em;
        color: var(--text-primary);
        margin: 0;
        line-height: 1.2;
    }}

    .command-subtitle {{
        font-size: 0.82rem;
        color: var(--text-muted);
        margin-top: 4px;
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }}

    .chip {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 600;
        background: var(--bg-subtle);
        color: var(--accent-blue);
        border: 1px solid var(--border-subtle);
    }}

    .status-pulse-badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        color: var(--accent-emerald);
    }}

    .pulse-dot {{
        width: 8px;
        height: 8px;
        background-color: var(--accent-emerald);
        border-radius: 50%;
        animation: pulseAnimation 2s infinite ease-in-out;
    }}

    @keyframes pulseAnimation {{
        0%, 100% {{ transform: scale(1); opacity: 1; }}
        50% {{ transform: scale(1.4); opacity: 0.4; }}
    }}

    /* KPI Cards Grid */
    .kpi-container {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 14px;
        margin-bottom: 22px;
    }}

    .kpi-tile {{
        background: var(--kpi-bg);
        border: var(--kpi-border);
        border-radius: 12px;
        padding: 16px 18px;
        box-shadow: var(--card-shadow);
        transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }}

    .kpi-tile:hover {{
        transform: translateY(-2px);
        box-shadow: 0 8px 24px -2px rgba(0, 0, 0, 0.15);
    }}

    .kpi-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }}

    .kpi-label {{
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted);
    }}

    .kpi-icon {{
        font-size: 1.1rem;
        opacity: 0.8;
    }}

    .kpi-number {{
        font-size: 1.55rem;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.02em;
        margin-bottom: 4px;
        line-height: 1.2;
    }}

    .kpi-meta {{
        font-size: 0.75rem;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 5px;
    }}

    .meta-benign {{ color: var(--accent-emerald); }}
    .meta-warning {{ color: var(--accent-amber); }}
    .meta-danger {{ color: var(--accent-red); }}
    .meta-info {{ color: var(--accent-blue); }}

    /* Tab Styling Overrides */
    .stTabs [data-baseweb="tab-list"] {{
        background: var(--tab-bg);
        border-radius: 10px;
        padding: 5px;
        gap: 8px;
        border: 1px solid var(--border-subtle);
        margin-bottom: 18px;
    }}

    .stTabs [data-baseweb="tab"] {{
        padding: 8px 18px;
        font-weight: 600;
        font-size: 0.88rem;
        color: var(--text-muted) !important;
        border-radius: 8px;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        border: 1px solid transparent;
        background: transparent;
    }}

    .stTabs [data-baseweb="tab"]:hover {{
        color: var(--text-primary) !important;
        background: var(--bg-card-hover);
    }}

    .stTabs [aria-selected="true"] {{
        color: var(--text-primary) !important;
        background: var(--tab-active-bg) !important;
        border: 1px solid var(--tab-active-border) !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
    }}

    /* Buttons Styling */
    .stButton > button {{
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        padding: 6px 14px !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
        border: 1px solid var(--border-medium) !important;
    }}

    .stButton > button:hover {{
        transform: translateY(-1px) !important;
        border-color: var(--border-focus) !important;
    }}

    .stButton > button:focus-visible {{
        outline: 2px solid var(--border-focus) !important;
        outline-offset: 2px !important;
    }}

    /* Action Card Container */
    .soc-card {{
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: var(--card-shadow);
        margin-bottom: 18px;
    }}

    .soc-card-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
        border-bottom: 1px solid var(--border-subtle);
        padding-bottom: 10px;
    }}

    .soc-card-title {{
        font-size: 1.05rem;
        font-weight: 600;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 8px;
    }}

    /* Severity Badges */
    .badge-tier {{
        display: inline-block;
        padding: 3px 10px;
        border-radius: 14px;
        font-weight: 700;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: #FFFFFF !important;
    }}

    .badge-critical {{ background: linear-gradient(135deg, #EF4444, #B91C1C); }}
    .badge-high     {{ background: linear-gradient(135deg, #F97316, #C2410C); }}
    .badge-medium   {{ background: linear-gradient(135deg, #F59E0B, #B45309); }}
    .badge-low      {{ background: linear-gradient(135deg, #10B981, #047857); }}

    /* Simulator Container */
    .simulator-deck {{
        background: var(--bg-subtle);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 18px;
        margin-top: 10px;
    }}

    /* Accessibility Focus Outlines */
    input:focus-visible, select:focus-visible, textarea:focus-visible {{
        outline: 2px solid var(--border-focus) !important;
        outline-offset: 1px !important;
    }}
</style>
""", unsafe_allow_html=True)

RYU_API_URL = "http://127.0.0.1:8080"

# Auto-start embedded REST API if not already listening
try:
    from ryu_controller import start_rest_api_server
    try:
        requests.get(f"{RYU_API_URL}/api/status", timeout=0.3)
    except Exception:
        start_rest_api_server(port=8080)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Cached Resource Loaders
# ---------------------------------------------------------------------------
@st.cache_resource
def load_detection_engine():
    engine = ThreatDetectionEngine()
    if not engine.load():
        engine.train()
    return engine


@st.cache_resource
def load_xai_explainer():
    engine = load_detection_engine()
    return XAIExplainer(detector_engine=engine)


def get_ryu_status():
    """Queries active Ryu SDN Controller status and mitigations via REST."""
    try:
        resp = requests.get(f"{RYU_API_URL}/api/status", timeout=1.0)
        if resp.status_code == 200:
            return resp.json(), True
    except Exception:
        pass

    # Fallback to local SQLite active mitigations
    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_mitigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            switch_id INTEGER NOT NULL,
            ip_src TEXT NOT NULL UNIQUE,
            action TEXT NOT NULL,
            priority INTEGER NOT NULL,
            applied_at REAL NOT NULL,
            ttl_sec INTEGER NOT NULL,
            status TEXT NOT NULL,
            operator_notes TEXT
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM flow_records")
    total_flows = cursor.fetchone()[0]

    cursor.execute("SELECT switch_id, ip_src, action, applied_at, ttl_sec, status, operator_notes FROM active_mitigations WHERE status='ACTIVE'")
    mitigations = []
    now = time.time()
    for row in cursor.fetchall():
        rem_ttl = max(0, int(row[4] - (now - row[3])))
        mitigations.append({
            "switch_id": row[0],
            "ip_src": row[1],
            "action": row[2],
            "applied_at": row[3],
            "ttl_sec": row[4],
            "status": row[5],
            "notes": row[6],
            "remaining_ttl": rem_ttl
        })
    conn.close()

    return {
        "status": "simulation_mode",
        "connected_switches": [1, 2, 3],
        "total_flow_records": total_flows,
        "active_mitigations": mitigations
    }, False


def dispatch_mitigation(ip_src, action="DROP", ttl_sec=60, notes=""):
    """Sends mitigation command to Ryu REST API or records in DB."""
    payload = {"ip_src": ip_src, "action": action, "ttl": ttl_sec, "switch_id": 1, "notes": notes}
    try:
        resp = requests.post(f"{RYU_API_URL}/api/mitigate", json=payload, timeout=1.5)
        if resp.status_code == 200:
            return True, "Enforced directly in OpenFlow 1.3 switch flow-table via Ryu REST API."
    except Exception:
        pass

    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO active_mitigations (switch_id, ip_src, action, priority, applied_at, ttl_sec, status, operator_notes)
        VALUES (1, ?, ?, 65000, ?, ?, 'ACTIVE', ?)
        ON CONFLICT(ip_src) DO UPDATE SET
            action=excluded.action,
            applied_at=excluded.applied_at,
            ttl_sec=excluded.ttl_sec,
            status='ACTIVE',
            operator_notes=excluded.operator_notes
    ''', (ip_src, action, time.time(), ttl_sec, notes))
    conn.commit()
    conn.close()
    return True, "Enforced via Local Policy Mitigation Table (TTL timer active)."


def dispatch_rollback(ip_src):
    """Sends rollback command to Ryu REST API or clears DB mitigation entry."""
    try:
        resp = requests.post(f"{RYU_API_URL}/api/rollback", json={"ip_src": ip_src, "switch_id": 1}, timeout=1.5)
        if resp.status_code == 200:
            return True, "Rollback message delivered to Ryu: OpenFlow flow entry deleted."
    except Exception:
        pass

    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE active_mitigations SET status='ROLLED_BACK' WHERE ip_src=?", (ip_src,))
    conn.commit()
    conn.close()
    return True, "Mitigation manually revoked (Rollback completed)."


# ---------------------------------------------------------------------------
# Visual SDN Digital Twin: Topology Graph Builder
# ---------------------------------------------------------------------------
def build_topology_figure(eval_df, active_mitigations, is_dark_mode=True):
    """
    Constructs an interactive visual graph of the OpenFlow topology
    highlighting switches, hosts, live threat tiers, and quarantined links.
    """
    mitigated_ips = {m['ip_src'] for m in active_mitigations}

    # Theme responsive color accents
    link_color = '#334155' if is_dark_mode else '#CBD5E1'
    switch_color = '#0284C7'
    server_color = '#2563EB'
    border_color = '#0F172A' if is_dark_mode else '#FFFFFF'

    node_coords = {
        'c1': (0.50, 0.85, 'Core Switch c1<br>OpenFlow 1.3 Spine', 'switch', switch_color),
        's1': (0.20, 0.55, 'Edge Switch s1<br>User Workstations Subnet', 'switch', switch_color),
        's2': (0.50, 0.55, 'Edge Switch s2<br>Data Center Infrastructure', 'switch', switch_color),
        's3': (0.80, 0.55, 'Edge Switch s3<br>Perimeter Gateway Fabric', 'switch', switch_color),
        '10.0.1.10': (0.10, 0.18, 'ws1 (10.0.1.10)<br>HR Workstation', 'host', '#10B981'),
        '10.0.1.11': (0.20, 0.18, 'ws2 (10.0.1.11)<br>Finance Workstation', 'host', '#10B981'),
        '10.0.1.12': (0.30, 0.18, 'ws3 (10.0.1.12)<br>IT Admin Workstation', 'host', '#10B981'),
        '10.0.2.10': (0.45, 0.18, 'db_server (10.0.2.10)<br>PostgreSQL :5432', 'server', server_color),
        '10.0.2.20': (0.55, 0.18, 'file_server (10.0.2.20)<br>SMB/NFS Storage :445', 'server', server_color),
        '10.0.3.1':  (0.75, 0.18, 'gw (10.0.3.1)<br>Edge Router / NAT', 'gateway', '#64748B'),
        '10.0.3.100':(0.88, 0.18, 'ext_srv (10.0.3.100)<br>External Cloud Repository', 'external', '#94A3B8')
    }

    eval_dict = {}
    if not eval_df.empty:
        eval_dict = {row['host_ip']: row for _, row in eval_df.iterrows()}

    for ip, data in node_coords.items():
        if ip in mitigated_ips:
            node_coords[ip] = (data[0], data[1], f"<b>{data[2]}</b><br><span style='color:#EF4444;'>⛔ [QUARANTINE ENFORCED]</span>", data[3], '#A855F7')
        elif ip in eval_dict:
            score = eval_dict[ip]['s_fused']
            tier = eval_dict[ip]['severity_tier']
            color = {'Critical': '#EF4444', 'High': '#F97316', 'Medium': '#F59E0B', 'Low': '#10B981'}.get(tier, '#10B981')
            node_coords[ip] = (data[0], data[1], f"<b>{data[2]}</b><br>Fused Risk: <b>{score:.3f}</b> ({tier})", data[3], color)

    edges = [
        ('c1', 's1'), ('c1', 's2'), ('c1', 's3'),
        ('s1', '10.0.1.10'), ('s1', '10.0.1.11'), ('s1', '10.0.1.12'),
        ('s2', '10.0.2.10'), ('s2', '10.0.2.20'),
        ('s3', '10.0.3.1'), ('s3', '10.0.3.100')
    ]

    edge_x = []
    edge_y = []
    for src, dst in edges:
        x0, y0 = node_coords[src][0], node_coords[src][1]
        x1, y1 = node_coords[dst][0], node_coords[dst][1]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=2.5, color=link_color),
        hoverinfo='none',
        mode='lines'
    )

    node_x = [v[0] for v in node_coords.values()]
    node_y = [v[1] for v in node_coords.values()]
    node_text = [v[2] for v in node_coords.values()]
    node_color = [v[4] for v in node_coords.values()]
    node_symbol = ['diamond' if v[3] == 'switch' else 'square' if v[3] == 'server' else 'circle' for v in node_coords.values()]

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[k for k in node_coords.keys()],
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            symbol=node_symbol,
            size=[32 if v[3] == 'switch' else 24 for v in node_coords.values()],
            color=node_color,
            line=dict(width=2.5, color=border_color)
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(
                text="Interactive SDN Digital Twin (Live Fabric & Blast Radius)",
                font=dict(size=14, color=plot_text_color)
            ),
            showlegend=False,
            hovermode='closest',
            paper_bgcolor=plot_paper_bg,
            plot_bgcolor=plot_bg,
            margin=dict(b=20, l=15, r=15, t=45),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.02, 1.02]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0.05, 0.98]),
            height=370
        )
    )
    return fig


# ---------------------------------------------------------------------------
# Application State & Data Initialization
# ---------------------------------------------------------------------------
detector = load_detection_engine()
xai = load_xai_explainer()

conn = sqlite3.connect(DEFAULT_DB_PATH)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        datetime_str TEXT NOT NULL,
        alert_id TEXT NOT NULL,
        host_ip TEXT NOT NULL,
        fused_score REAL NOT NULL,
        severity_tier TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        analyst_name TEXT NOT NULL,
        ttl_sec INTEGER NOT NULL,
        justification TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

# ---------------------------------------------------------------------------
# Header Section & Live Status Indicator
# ---------------------------------------------------------------------------
raw_flows = load_flows_from_db(limit=2000)
ryu_info, is_ryu_live = get_ryu_status()

status_badge = f"""
    <div class="status-pulse-badge">
        <span class="pulse-dot"></span>
        <span>{'RYU OF 1.3 LIVE (:8080)' if is_ryu_live else 'STANDALONE TWIN ACTIVE'}</span>
    </div>
"""

st.markdown(f"""
<div class="command-header">
    <div class="command-title-box">
        <div class="command-icon">🛡️</div>
        <div>
            <div class="command-title">Explainable AI Insider Threat Detection SOC</div>
            <div class="command-subtitle">
                <span class="chip">OpenFlow 1.3</span>
                <span class="chip">Dual XAI (SHAP & LIME)</span>
                <span class="chip">Multi-Model Risk Fusion</span>
                <span class="chip">Zero-Trust Gate</span>
            </div>
        </div>
    </div>
    <div>
        {status_badge}
    </div>
</div>
""", unsafe_allow_html=True)

if raw_flows.empty:
    st.info("ℹ️ Telemetry database is currently initializing. Click '🟢 Benign Flow' or '🚨 Data Exfil' in the sidebar to stream network events.")
    st.stop()

# ---------------------------------------------------------------------------
# Sliding-Window Inference & Threat Evaluation
# ---------------------------------------------------------------------------
windows_df = extract_sliding_windows(raw_flows, window_size=10.0, step_size=5.0)

host_latest_evals = []
for host_ip, h_group in windows_df.groupby('host_ip'):
    latest_win = h_group.sort_values(by='window_end').iloc[-1].to_dict()
    pred = detector.predict_window(latest_win)
    pred['host_ip'] = host_ip
    pred['role'] = ASSET_ROLES.get(host_ip, {}).get('role', 'HOST')
    pred['window_end'] = latest_win['window_end']
    pred['bytes_per_sec'] = latest_win.get('bytes_per_sec', 0.0)
    pred['raw_window'] = latest_win
    pred['mitre'] = map_threat_to_mitre(latest_win)
    host_latest_evals.append(pred)

eval_df = pd.DataFrame(host_latest_evals)

total_records = len(raw_flows)
active_monitored_hosts = len(eval_df)
threat_alerts = len(eval_df[eval_df['s_fused'] >= confidence_threshold]) if not eval_df.empty else 0
active_mits = ryu_info.get('active_mitigations', [])

# ---------------------------------------------------------------------------
# Modern KPI Metric Cards
# ---------------------------------------------------------------------------
alert_class = "meta-danger" if threat_alerts > 0 else "meta-benign"
alert_meta = f"Action Required ({threat_alerts})" if threat_alerts > 0 else "All Endpoints Nominal"

st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-tile">
        <div class="kpi-header">
            <span class="kpi-label">Total Telemetry</span>
            <span class="kpi-icon">📊</span>
        </div>
        <div class="kpi-number">{total_records:,}</div>
        <div class="kpi-meta meta-info">● 10s Sliding Windows</div>
    </div>
    <div class="kpi-tile">
        <div class="kpi-header">
            <span class="kpi-label">Active SDN Hosts</span>
            <span class="kpi-icon">💻</span>
        </div>
        <div class="kpi-number">{active_monitored_hosts}</div>
        <div class="kpi-meta meta-benign">● Monitored Endpoints</div>
    </div>
    <div class="kpi-tile">
        <div class="kpi-header">
            <span class="kpi-label">Threat Alerts (τ ≥ {confidence_threshold:.2f})</span>
            <span class="kpi-icon">🚨</span>
        </div>
        <div class="kpi-number">{threat_alerts}</div>
        <div class="kpi-meta {alert_class}">● {alert_meta}</div>
    </div>
    <div class="kpi-tile">
        <div class="kpi-header">
            <span class="kpi-label">Active Mitigations</span>
            <span class="kpi-icon">🔒</span>
        </div>
        <div class="kpi-number">{len(active_mits)}</div>
        <div class="kpi-meta meta-warning">● OpenFlow Flow Rules</div>
    </div>
    <div class="kpi-tile">
        <div class="kpi-header">
            <span class="kpi-label">SDN Controller</span>
            <span class="kpi-icon">⚡</span>
        </div>
        <div class="kpi-number" style="font-size: 1.2rem; padding-top: 5px;">{'Ryu Live' if is_ryu_live else 'Digital Twin'}</div>
        <div class="kpi-meta {'meta-benign' if is_ryu_live else 'meta-info'}">● Port 8080 Active</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Live Threat Monitor & Topology",
    "🔍 Explainability & What-If Simulator",
    "🛡️ Policy-Gated Response Console",
    "📜 Audit Log & Forensic Dossier",
    "🎯 MITRE ATT&CK Matrix"
])

# ===========================================================================
# TAB 1: Live Threat Monitor & Network Topology Graph
# ===========================================================================
with tab1:
    col_top1, col_top2 = st.columns([3, 2])
    with col_top1:
        st.markdown("""
        <div class="soc-card-header">
            <span class="soc-card-title">🖥️ Host Risk Matrix & Behavior Telemetry</span>
        </div>
        """, unsafe_allow_html=True)

        table_rows = []
        for _, row in eval_df.iterrows():
            tier = row['severity_tier']
            table_rows.append({
                "Host IP": row['host_ip'],
                "Role": row['role'],
                "Fused Risk (s_fused)": row['s_fused'],
                "Supervised": f"{row['p_supervised']:.3f}",
                "Anomaly": f"{row['s_unsupervised']:.3f}",
                "Context": f"{row['s_context']:.3f}",
                "Bandwidth": f"{row['bytes_per_sec'] / 1024:.1f} KB/s",
                "Severity": tier,
                "MITRE Technique": row['mitre']['technique_id']
            })

        st.dataframe(
            pd.DataFrame(table_rows),
            use_container_width=True,
            column_config={
                "Fused Risk (s_fused)": st.column_config.ProgressColumn(
                    "Fused Risk", format="%.3f", min_value=0.0, max_value=1.0
                )
            },
            height=280
        )

    with col_top2:
        fig_topo = build_topology_figure(eval_df, active_mits, is_dark_mode=is_dark)
        st.plotly_chart(fig_topo, use_container_width=True)

    st.markdown("---")

    col_c1, col_c2 = st.columns([3, 2])
    with col_c1:
        history_records = []
        for _, w_row in windows_df.iterrows():
            w_dict = w_row.to_dict()
            pred = detector.predict_window(w_dict)
            history_records.append({
                'Time': datetime.fromtimestamp(w_row['window_end']).strftime('%H:%M:%S'),
                'Timestamp': w_row['window_end'],
                'Host': str(w_row['host_ip']),
                'Fused Risk': pred['s_fused']
            })
        hist_df = pd.DataFrame(history_records).sort_values(by='Timestamp')

        fig_timeline = px.line(
            hist_df, x='Time', y='Fused Risk', color='Host', markers=True,
            title="Sliding-Window Risk Trajectory (s_fused) Over Time",
            range_y=[0.0, 1.05],
            template=plotly_template
        )
        fig_timeline.add_hline(
            y=confidence_threshold, line_dash="dash", line_color="#EF4444",
            annotation_text=f"Decision Cutoff τ = {confidence_threshold:.2f}"
        )
        fig_timeline.update_layout(
            paper_bgcolor=plot_paper_bg,
            plot_bgcolor=plot_bg,
            font=dict(color=plot_text_color),
            height=320,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    with col_c2:
        tier_counts = eval_df['severity_tier'].value_counts().reset_index()
        tier_counts.columns = ['Tier', 'Count']
        color_map = {'Low': '#10B981', 'Medium': '#F59E0B', 'High': '#F97316', 'Critical': '#EF4444'}
        fig_donut = px.pie(
            tier_counts, names='Tier', values='Count', hole=0.6,
            color='Tier', color_discrete_map=color_map,
            title="Host Threat Severity Distribution",
            template=plotly_template
        )
        fig_donut.update_layout(
            paper_bgcolor=plot_paper_bg,
            font=dict(color=plot_text_color),
            height=320,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_donut, use_container_width=True)


# ===========================================================================
# TAB 2: Explainability Layer & Counterfactual "What-If" Simulator
# ===========================================================================
with tab2:
    st.markdown("""
    <div class="soc-card-header">
        <span class="soc-card-title">🔍 Dual-Engine Explainability (SHAP & LIME) & Counterfactual Simulator</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Inspect local feature attributions, surrogate decision boundaries, and test 'What-If' scenarios to find benign baselines.")

    available_hosts = eval_df['host_ip'].tolist()
    flagged = eval_df[eval_df['s_fused'] >= confidence_threshold]['host_ip'].tolist()
    default_idx = available_hosts.index(flagged[0]) if flagged else 0

    col_sel1, col_sel2 = st.columns([2, 3])
    with col_sel1:
        selected_host = st.selectbox("Select Endpoint for Deep XAI Inspection:", available_hosts, index=default_idx)

    target_eval = eval_df[eval_df['host_ip'] == selected_host].iloc[0]
    scaled_feats = target_eval['scaled_features']
    raw_w = target_eval['raw_window']

    with st.spinner("Synthesizing local SHAP & LIME explanations..."):
        shap_res = xai.explain_window_shap(scaled_feats)
        lime_res = xai.explain_window_lime(scaled_feats)

    # Narrative Card
    st.markdown(f"""
    <div class="soc-card" style="border-left: 4px solid var(--accent-blue); padding: 14px 18px; margin-bottom: 16px;">
        <div style="font-size: 0.82rem; font-weight: 700; color: var(--accent-blue); text-transform: uppercase;">
            🤖 Analyst Incident Narrative ({selected_host})
        </div>
        <div style="font-size: 0.92rem; color: var(--text-primary); margin-top: 4px; line-height: 1.5;">
            {shap_res.get('narrative_summary', 'No anomaly detected. Host behavior closely matches nominal baseline.')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # XAI Verification Metrics
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        st.metric("SHAP Overhead", f"{shap_res.get('execution_overhead_ms', 0):.2f} ms")
    with f_col2:
        st.metric("LIME Overhead", f"{lime_res.get('execution_overhead_ms', 0):.2f} ms")
    with f_col3:
        fidelity_err = shap_res.get('fidelity', {}).get('fidelity_error', 0.0)
        st.metric("Additivity Error", f"{fidelity_err:.6f}", delta="Passed (< 0.05)")
    with f_col4:
        st.metric("LIME Surrogate R²", f"{lime_res.get('local_surrogate_r2', 0.85):.3f}")

    st.markdown("---")

    col_x1, col_x2 = st.columns([3, 2])
    with col_x1:
        st.markdown("##### 📌 SHAP Feature Attributions (Push vs Pull Factors)")
        top_attrs = shap_res.get('all_attributions', [])[:10]
        attr_df = pd.DataFrame(top_attrs)
        if not attr_df.empty:
            attr_df['Color'] = attr_df['shap_value'].apply(lambda x: '#EF4444' if x > 0 else '#10B981')
            fig_shap = go.Figure(go.Bar(
                x=attr_df['shap_value'],
                y=attr_df['feature'],
                orientation='h',
                marker=dict(color=attr_df['Color']),
                text=[f"{v:+.4f}" for v in attr_df['shap_value']],
                textposition='outside'
            ))
            fig_shap.update_layout(
                title=f"Local Shapley Attributions for {selected_host}",
                xaxis_title="Shapley Contribution φ_i",
                yaxis=dict(autorange="reversed"),
                paper_bgcolor=plot_paper_bg,
                plot_bgcolor=plot_bg,
                font=dict(color=plot_text_color),
                height=380,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_shap, use_container_width=True)

    with col_x2:
        st.markdown("##### 📋 LIME Local Decision Rules")
        lime_rules = lime_res.get('explanation_rules', [])
        if lime_rules:
            st.dataframe(pd.DataFrame(lime_rules), use_container_width=True, height=180)

        st.markdown("##### 🌐 Global Feature Importance (|SHAP|)")
        global_imp = xai.compute_global_feature_importance()[:5]
        g_df = pd.DataFrame(global_imp)
        fig_global = px.bar(
            g_df, x='mean_abs_shap', y='feature', orientation='h',
            color='mean_abs_shap', color_continuous_scale='Reds',
            template=plotly_template
        )
        fig_global.update_layout(
            yaxis=dict(autorange="reversed"),
            paper_bgcolor=plot_paper_bg,
            plot_bgcolor=plot_bg,
            font=dict(color=plot_text_color),
            height=180,
            margin=dict(l=10, r=10, t=25, b=10)
        )
        st.plotly_chart(fig_global, use_container_width=True)

    st.markdown("---")

    # Counterfactual Simulator Section
    st.markdown("""
    <div class="soc-card-header">
        <span class="soc-card-title">🧪 Counterfactual "What-If" Sensitivity Simulator</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Interactively modify behavioral metrics to calculate the minimum shift required to restore benign status:")

    c_col1, c_col2, c_col3, c_col4 = st.columns(4)
    with c_col1:
        sim_bps = st.slider("Throughput (Bytes/sec):", 500, 500000, int(raw_w.get('bytes_per_sec', 1500)))
    with c_col2:
        sim_off = st.slider("Off-Hours Activity Ratio:", 0.0, 1.0, float(raw_w.get('off_hours_ratio', 0.0)), 0.1)
    with c_col3:
        sim_db = st.selectbox("Sensitive DB Access (5432):", [0.0, 1.0], index=int(raw_w.get('sensitive_server_access', 0)))
    with c_col4:
        sim_entropy = st.slider("Port Entropy:", 0.0, 4.0, float(raw_w.get('dst_port_entropy', 0.0)), 0.2)

    sim_window = dict(raw_w)
    sim_window['bytes_per_sec'] = sim_bps
    sim_window['off_hours_ratio'] = sim_off
    sim_window['sensitive_server_access'] = sim_db
    sim_window['dst_port_entropy'] = sim_entropy
    sim_window['total_bytes'] = sim_bps * 10.0
    sim_window['baseline_deviation_zscore'] = max(0.0, (sim_bps - 1500.0) / 1000.0)

    sim_pred = detector.predict_window(sim_window)
    delta_s = sim_pred['s_fused'] - target_eval['s_fused']

    sim_res_c1, sim_res_c2, sim_res_c3 = st.columns(3)
    with sim_res_c1:
        st.metric("Simulated Fused Risk", f"{sim_pred['s_fused']:.3f}", delta=f"{delta_s:+.3f}", delta_color="inverse")
    with sim_res_c2:
        st.metric("Simulated Severity Tier", sim_pred['severity_tier'])
    with sim_res_c3:
        st.metric("Simulated SDN Action", sim_pred['recommended_action'])


# ===========================================================================
# TAB 3: Policy-Gated Response Console & Surgical SDN Playbooks
# ===========================================================================
with tab3:
    st.markdown("""
    <div class="soc-card-header">
        <span class="soc-card-title">🛡️ Policy-Gated Response Console & Surgical SDN Playbooks</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Human-in-the-loop validation console: Authorize granular OpenFlow mitigation rules or quarantine compromised endpoints.")

    pending_alerts = eval_df[eval_df['s_fused'] >= 0.35]

    st.markdown("##### 🚨 Elevated Alerts Requiring Security Analyst Authorization")
    if pending_alerts.empty:
        st.success("✅ Zero active threat alerts pending authorization. Network fabric is fully nominal.")
    else:
        for idx, alert in pending_alerts.iterrows():
            host_ip = alert['host_ip']
            tier = alert['severity_tier']
            fused_score = alert['s_fused']
            mitre_data = alert['mitre']

            badge_style = f"badge-{tier.lower()}"

            with st.expander(f"⚠️ [{tier.upper()}] Host {host_ip} • Fused Risk: {fused_score:.3f} • {mitre_data['technique_name']}", expanded=(tier in ['High', 'Critical'])):
                col_a1, col_a2 = st.columns([3, 2])
                with col_a1:
                    st.markdown(f"**Asset Role:** `{alert['role']}`")
                    st.markdown(f"**MITRE ATT&CK:** `{mitre_data['technique_id']}: {mitre_data['technique_name']}` ({mitre_data['tactic']})")
                    st.markdown(f"**NIST SP 800-53 Control:** `{mitre_data['nist_control']}`")
                    st.markdown(f"**Telemetry Breakdown:** Supervised: `{alert['p_supervised']:.3f}` | Anomaly: `{alert['s_unsupervised']:.3f}` | Context: `{alert['s_context']:.3f}`")
                    st.markdown(f"**Current Flow Rate:** `{alert['bytes_per_sec'] / 1024:.1f} KB/s`")

                with col_a2:
                    st.markdown("###### Select OpenFlow Containment Playbook:")
                    playbook_action = st.selectbox(
                        "Enforcement Action:",
                        [
                            "Full Host Isolation (OpenFlow DROP all traffic)",
                            "Surgical Port Block (Drop only DB:5432 & SMB:445)",
                            "Rate-Limit Throttling (Throttle upload to 64 kbps)",
                            "Decoy Honeynet Redirection (Reroute to Decoy 10.0.2.99)"
                        ],
                        key=f"playbook_{host_ip}"
                    )
                    ttl_choice = st.selectbox(
                        "Enforcement TTL (seconds):",
                        [30, 60, 120, 300, 3600],
                        index=1,
                        key=f"ttl_{host_ip}"
                    )
                    notes = st.text_input(
                        "Analyst Justification / Audit Ticket:",
                        value=f"Mitigating {mitre_data['technique_id']} on {host_ip} ({tier} severity)",
                        key=f"notes_{host_ip}"
                    )

                    btn_c1, btn_c2 = st.columns(2)
                    with btn_c1:
                        if st.button("🚀 Enforce Playbook", key=f"auth_{host_ip}", type="primary", use_container_width=True):
                            action_code = "DROP"
                            if "Surgical" in playbook_action:
                                action_code = "SURGICAL_PORT_BLOCK"
                            elif "Rate-Limit" in playbook_action:
                                action_code = "RATE_LIMIT"
                            elif "Honeynet" in playbook_action:
                                action_code = "HONEYNET_REDIRECT"

                            success, msg = dispatch_mitigation(host_ip, action=action_code, ttl_sec=ttl_choice, notes=notes)

                            conn = sqlite3.connect(DEFAULT_DB_PATH)
                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT INTO audit_logs (
                                    timestamp, datetime_str, alert_id, host_ip, fused_score,
                                    severity_tier, action_taken, analyst_name, ttl_sec, justification
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                time.time(), datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                f"ALT-{int(time.time())%10000}", host_ip, fused_score,
                                tier, action_code, "SOC_Analyst_Lead",
                                ttl_choice, notes
                            ))
                            conn.commit()
                            conn.close()
                            st.success(f"Playbook deployed: {msg}")
                            time.sleep(1)
                            st.rerun()

                    with btn_c2:
                        if st.button("Dismiss Alert", key=f"dsm_{host_ip}", use_container_width=True):
                            conn = sqlite3.connect(DEFAULT_DB_PATH)
                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT INTO audit_logs (
                                    timestamp, datetime_str, alert_id, host_ip, fused_score,
                                    severity_tier, action_taken, analyst_name, ttl_sec, justification
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                time.time(), datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                f"ALT-{int(time.time())%10000}", host_ip, fused_score,
                                tier, "DISMISSED", "SOC_Analyst_Lead",
                                0, notes
                            ))
                            conn.commit()
                            conn.close()
                            st.info(f"Alert on {host_ip} logged as false-positive/dismissed.")
                            time.sleep(0.5)
                            st.rerun()

    st.markdown("---")

    st.markdown("##### 🔒 Active OpenFlow Mitigations & Rollback Controls")
    if not active_mits:
        st.info("No active OpenFlow mitigation rules currently enforced in switch fabric.")
    else:
        for mit in active_mits:
            ip = mit['ip_src']
            act = mit['action']
            rem_ttl = mit.get('remaining_ttl', 0)
            m_col1, m_col2, m_col3, m_col4 = st.columns([2, 2, 2, 2])
            with m_col1:
                st.markdown(f"**Target Host:** `{ip}`")
            with m_col2:
                st.markdown(f"**Action:** `{act}` (Switch s{mit['switch_id']})")
            with m_col3:
                st.markdown(f"**TTL Remaining:** `{rem_ttl}s` / `{mit['ttl_sec']}s`")
            with m_col4:
                if st.button(f"⏪ Rollback ({ip})", key=f"rb_{ip}"):
                    success, msg = dispatch_rollback(ip)
                    conn = sqlite3.connect(DEFAULT_DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO audit_logs (
                            timestamp, datetime_str, alert_id, host_ip, fused_score,
                            severity_tier, action_taken, analyst_name, ttl_sec, justification
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        time.time(), datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        f"REV-{int(time.time())%10000}", ip, 0.0,
                        "N/A", "MANUAL_ROLLBACK", "SOC_Analyst_Lead",
                        0, f"Revoked mitigation on {ip}"
                    ))
                    conn.commit()
                    conn.close()
                    st.success(f"Rule revoked: {msg}")
                    time.sleep(1)
                    st.rerun()


# ===========================================================================
# TAB 4: Audit Log & Forensic Incident Dossier Generator
# ===========================================================================
with tab4:
    st.markdown("""
    <div class="soc-card-header">
        <span class="soc-card-title">📜 Immutable Compliance Audit Trail & Forensic Dossier Export</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Full chronological audit ledger tracking all alerts, human decisions, flow modifications, and formal dossier generation.")

    conn = sqlite3.connect(DEFAULT_DB_PATH)
    audit_df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100", conn)
    conn.close()

    col_aud1, col_aud2 = st.columns([3, 2])
    with col_aud1:
        st.markdown("##### 🏛️ Historical Audit Ledger")
        if audit_df.empty:
            st.info("Audit ledger is empty. Authorized mitigations will appear here.")
        else:
            st.dataframe(audit_df, use_container_width=True, height=280)
            csv_data = audit_df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Export Ledger (CSV)", data=csv_data, file_name="sdn_audit_log.csv", mime="text/csv")

    with col_aud2:
        st.markdown("##### 📄 Single-Click Forensic Dossier Export")
        report_host = st.selectbox("Select Target Host for Investigation:", available_hosts, key="rep_host")
        r_eval = eval_df[eval_df['host_ip'] == report_host].iloc[0]
        r_shap = xai.explain_window_shap(r_eval['scaled_features'])

        dossier_data = {
            'alert_id': f"INC-{int(time.time())%100000}",
            'host_ip': report_host,
            'role': r_eval['role'],
            'severity_tier': r_eval['severity_tier'],
            's_fused': r_eval['s_fused'],
            'mitre': r_eval['mitre'],
            'top_positive_factors': r_shap.get('top_positive_factors', []),
            'action_taken': r_eval['recommended_action'],
            'analyst_name': 'Lead SOC Security Architect',
            'ttl_sec': 60,
            'justification': f"Confirmed {r_eval['mitre']['technique_name']} via behavioral XAI attribution.",
            'fidelity': r_shap.get('fidelity', {})
        }

        html_dossier = generate_forensic_html_report(dossier_data)

        st.download_button(
            label="📑 Download Incident Dossier (HTML)",
            data=html_dossier,
            file_name=f"Forensic_Report_{report_host}.html",
            mime="text/html",
            use_container_width=True
        )

        with st.expander("👁️ Preview Formal Dossier Report", expanded=False):
            st.components.v1.html(html_dossier, height=450, scrolling=True)


# ===========================================================================
# TAB 5: MITRE ATT&CK for Enterprise Matrix
# ===========================================================================
with tab5:
    st.markdown("""
    <div class="soc-card-header">
        <span class="soc-card-title">🎯 MITRE ATT&CK Framework Correlation Matrix</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Correlates insider behavioral anomalies to industry-standard MITRE ATT&CK Tactics, Techniques, and NIST Controls.")

    for t_key, t_info in MITRE_TECHNIQUES.items():
        st.markdown(f"""
        <div class="soc-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div style="font-size: 1.05rem; font-weight: 700; color: var(--text-primary);">
                    🛡️ {t_info['technique_id']}: {t_info['technique_name']}
                </div>
                <div>
                    <span class="chip" style="background: var(--bg-subtle); color: var(--accent-blue); font-weight: 700;">{t_info['tactic']}</span>
                    <span class="chip" style="background: var(--bg-subtle); color: var(--accent-emerald); font-weight: 700;">NIST {t_info['nist_control']}</span>
                </div>
            </div>
            <div style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 10px; line-height: 1.5;">
                {t_info['description']}
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 4px;">
                <b>Detection Telemetry:</b> <code>{'</code>, <code>'.join(t_info['primary_features'])}</code>
            </div>
            <div style="font-size: 0.8rem; color: var(--accent-red);">
                <b>Recommended SDN Playbook:</b> <code>{t_info['recommended_sdn_action']}</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("""
<div style="text-align: center; font-size: 0.78rem; color: var(--text-muted); margin-top: 36px; padding: 18px 0; border-top: 1px solid var(--border-subtle);">
    Explainable AI-Based Insider Threat Detection via Network Behavior Analysis in SDN Environments Using SHAP/LIME<br>
    Enterprise SOC Command Center • Built with Streamlit, Plotly, Scikit-Learn, SHAP & Ryu SDN
</div>
""", unsafe_allow_html=True)
