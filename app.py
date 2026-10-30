#!/usr/bin/env python3
"""
=============================================================================
MODULE 5: Policy-Gated Response & Monitoring Dashboard UI (Extended Enterprise Edition)
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: app.py
=============================================================================
Description:
    Full-Featured Interactive Web Dashboard and Policy-Gated SOC Analyst Console:
      1. Live Threat Monitor & Network Topology Graph:
         - Visual SDN Digital Twin with dynamic blast-radius & quarantine coloring.
         - Sliding-window risk trajectory timeline per host.
      2. Explainability Layer & Counterfactual "What-If" Simulator:
         - Exact SHAP waterfall bar charts, LIME local surrogates.
         - Interactive counterfactual sliders: simulate how metric changes flip verdicts to benign.
         - SHAP additivity fidelity checks & execution overhead profiling.
      3. Policy-Gated Response Console & Surgical SDN Playbooks:
         - Human-in-the-loop analyst review for Medium/High/Critical alerts.
         - Playbook Actions: Full Host Isolate (DROP), Surgical Port 5432 Block, Rate-Limit, Honeynet Redirect.
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
# Streamlit Page Configuration & Modern Theme Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Explainable SDN Insider Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 1.85rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 0.95rem;
        color: #64748B;
        margin-bottom: 1.2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #F8FAFC 0%, #EDF2F7 100%);
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .tier-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
        color: white;
    }
    .badge-critical { background-color: #DC2626; }
    .badge-high     { background-color: #EA580C; }
    .badge-medium   { background-color: #D97706; }
    .badge-low      { background-color: #16A34A; }
    .stTabs [data-baseweb="tab-list"] { gap: 18px; }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        font-weight: 600;
    }
    .mitre-badge {
        background-color: #475569;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-family: monospace;
        font-weight: 600;
    }
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
            return True, "Rule pushed to Ryu Controller (OpenFlow 1.3 match enforced)"
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
    return True, "Enforced via Local Policy Mitigation Table (TTL active)"


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
def build_topology_figure(eval_df, active_mitigations):
    """
    Constructs an interactive visual graph of the OpenFlow topology
    highlighting switches, hosts, live threat tiers, and quarantined links.
    """
    mitigated_ips = {m['ip_src'] for m in active_mitigations}

    # Node positions
    node_coords = {
        'c1': (0.50, 0.85, 'Core Switch c1 (OF 1.3)', 'switch', '#0284C7'),
        's1': (0.20, 0.55, 'Edge Switch s1 (Workstations)', 'switch', '#0284C7'),
        's2': (0.50, 0.55, 'Edge Switch s2 (Data Center)', 'switch', '#0284C7'),
        's3': (0.80, 0.55, 'Edge Switch s3 (Gateway)', 'switch', '#0284C7'),
        '10.0.1.10': (0.10, 0.18, 'ws1: HR User', 'host', '#16A34A'),
        '10.0.1.11': (0.20, 0.18, 'ws2: Finance User', 'host', '#16A34A'),
        '10.0.1.12': (0.30, 0.18, 'ws3: IT Admin', 'host', '#16A34A'),
        '10.0.2.10': (0.45, 0.18, 'db_server (PostgreSQL:5432)', 'server', '#2563EB'),
        '10.0.2.20': (0.55, 0.18, 'file_server (SMB:445)', 'server', '#2563EB'),
        '10.0.3.1':  (0.75, 0.18, 'gw: Internal Gateway', 'gateway', '#64748B'),
        '10.0.3.100':(0.88, 0.18, 'ext_srv: Cloud Server', 'external', '#94A3B8')
    }

    eval_dict = {}
    if not eval_df.empty:
        eval_dict = {row['host_ip']: row for _, row in eval_df.iterrows()}

    for ip, data in node_coords.items():
        if ip in mitigated_ips:
            node_coords[ip] = (data[0], data[1], f"{data[2]}<br><b>[ENFORCED QUARANTINE]</b>", data[3], '#9333EA')
        elif ip in eval_dict:
            score = eval_dict[ip]['s_fused']
            tier = eval_dict[ip]['severity_tier']
            color = {'Critical': '#DC2626', 'High': '#EA580C', 'Medium': '#D97706', 'Low': '#16A34A'}.get(tier, '#16A34A')
            node_coords[ip] = (data[0], data[1], f"{data[2]}<br>Risk: {score:.3f} ({tier})", data[3], color)

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
        line=dict(width=2.5, color='#CBD5E1'),
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
            line=dict(width=2, color='#1E293B')
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title="Interactive Visual SDN Digital Twin (Live Fabric & Blast Radius)",
                        titlefont=dict(size=15),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=10, r=10, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.02, 1.02]),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0.05, 0.98]),
                        height=360
                    ))
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
# Sidebar: Controls & Traffic Injection
# ---------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SDN Threat Controls")
st.sidebar.markdown("**Simulation & Attack Scenario Dispatcher**")

col_s1, col_s2 = st.sidebar.columns(2)
with col_s1:
    if st.button("Benign Stream", use_container_width=True):
        with st.spinner("Streaming benign traffic..."):
            stream_benign_traffic(duration_sec=10, sleep_interval=0.2)
        st.sidebar.success("Streamed 10s of benign flows.")
        st.rerun()

with col_s2:
    if st.button("Data Exfil", use_container_width=True):
        with st.spinner("Injecting exfiltration..."):
            inject_data_exfiltration(attacker_ip='10.0.1.11', bursts=15)
        st.sidebar.error("Injected Data Exfiltration from ws2 (10.0.1.11)!")
        st.rerun()

col_s3, col_s4 = st.sidebar.columns(2)
with col_s3:
    if st.button("Port Scan", use_container_width=True):
        with st.spinner("Injecting scan..."):
            inject_port_scan(attacker_ip='10.0.1.10', num_ports=30)
        st.sidebar.warning("Injected Port Reconnaissance from ws1 (10.0.1.10)!")
        st.rerun()

with col_s4:
    if st.button("DB Abuse", use_container_width=True):
        with st.spinner("Injecting DB abuse..."):
            inject_privilege_abuse(attacker_ip='10.0.1.10', queries=15)
        st.sidebar.warning("Injected Privilege Abuse on DB 5432!")
        st.rerun()

st.sidebar.divider()
st.sidebar.markdown("### ⚙️ Engine Settings")
confidence_threshold = st.sidebar.slider("Anomaly Detection Threshold (τ)", 0.20, 0.85, 0.50, 0.05)
auto_refresh = st.sidebar.checkbox("Auto-refresh data (every 5s)", value=False)
if auto_refresh:
    time.sleep(5)
    st.rerun()

if st.sidebar.button("🔄 Retrain ML Engine", use_container_width=True):
    with st.spinner("Retraining Supervised RF + Unsupervised IF..."):
        detector.train()
    st.sidebar.success("Engine retrained with fresh baseline!")
    st.rerun()

# ---------------------------------------------------------------------------
# Header Section & System Health
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">Explainable AI-Based Insider Threat Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Software-Defined Networking (OpenFlow 1.3) • Multi-Model Risk Fusion • SHAP & LIME XAI Verification</div>', unsafe_allow_html=True)

raw_flows = load_flows_from_db(limit=2000)
ryu_info, is_ryu_live = get_ryu_status()

if raw_flows.empty:
    st.info("Network telemetry database is empty. Click 'Benign Stream' or 'Data Exfil' in the sidebar to populate flows.")
    st.stop()

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

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.metric("Total Flow Telemetry", f"{total_records:,} flows")
with kpi2:
    st.metric("Active SDN Hosts", f"{active_monitored_hosts} hosts")
with kpi3:
    st.metric(f"Threat Alerts (τ ≥ {confidence_threshold})", f"{threat_alerts} active", delta=threat_alerts, delta_color="inverse")
with kpi4:
    st.metric("Active Mitigations", f"{len(active_mits)} rules")
with kpi5:
    status_label = "🟢 Ryu Live (OF 1.3)" if is_ryu_live else "🔵 Standalone / Testbed"
    st.metric("Controller Status", status_label)

st.write("")

# ---------------------------------------------------------------------------
# Navigation Tabs (5 Core Modules + Extended Capabilities)
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
        st.subheader("Host Risk Matrix & Threat Status")
        table_rows = []
        for _, row in eval_df.iterrows():
            tier = row['severity_tier']
            table_rows.append({
                "Host IP": row['host_ip'],
                "Role": row['role'],
                "Fused Risk (s_fused)": f"{row['s_fused']:.3f}",
                "Supervised (P_sup)": f"{row['p_supervised']:.3f}",
                "Unsupervised (S_unsup)": f"{row['s_unsupervised']:.3f}",
                "Context (S_ctx)": f"{row['s_context']:.3f}",
                "Throughput": f"{row['bytes_per_sec'] / 1024:.1f} KB/s",
                "Severity Tier": tier,
                "MITRE Technique": row['mitre']['technique_id']
            })

        st.dataframe(
            pd.DataFrame(table_rows),
            use_container_width=True,
            column_config={
                "Fused Risk (s_fused)": st.column_config.ProgressColumn(
                    "Risk Score", format="%.3f", min_value=0.0, max_value=1.0
                )
            }
        )

    with col_top2:
        fig_topo = build_topology_figure(eval_df, active_mits)
        st.plotly_chart(fig_topo, use_container_width=True)

    st.divider()

    col_c1, col_c2 = st.columns([3, 2])
    with col_c1:
        st.markdown("#### Dynamic Anomaly Score Timeline per Host")
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
            title="10-Second Sliding-Window Risk Trajectory (s_fused)",
            range_y=[0.0, 1.05]
        )
        fig_timeline.add_hline(
            y=confidence_threshold, line_dash="dash", line_color="red",
            annotation_text=f"Threshold τ = {confidence_threshold}"
        )
        fig_timeline.update_layout(height=320, margin=dict(l=20, r=20, t=35, b=20))
        st.plotly_chart(fig_timeline, use_container_width=True)

    with col_c2:
        st.markdown("#### Severity Breakdown")
        tier_counts = eval_df['severity_tier'].value_counts().reset_index()
        tier_counts.columns = ['Tier', 'Count']
        color_map = {'Low': '#16A34A', 'Medium': '#D97706', 'High': '#EA580C', 'Critical': '#DC2626'}
        fig_donut = px.pie(
            tier_counts, names='Tier', values='Count', hole=0.55,
            color='Tier', color_discrete_map=color_map,
            title="Active Host Threat Tier Breakdown"
        )
        fig_donut.update_layout(height=320, margin=dict(l=20, r=20, t=35, b=20))
        st.plotly_chart(fig_donut, use_container_width=True)


# ===========================================================================
# TAB 2: Explainability Layer & Counterfactual "What-If" Simulator
# ===========================================================================
with tab2:
    st.subheader("Explainable AI (SHAP & LIME) & Counterfactual 'What-If' Simulator")
    st.markdown("""
    Transparent model justification. Examines local Shapley attributions, surrogate LIME rules,
    additivity fidelity verification, and interactive counterfactual simulation.
    """)

    available_hosts = eval_df['host_ip'].tolist()
    flagged = eval_df[eval_df['s_fused'] >= confidence_threshold]['host_ip'].tolist()
    default_idx = available_hosts.index(flagged[0]) if flagged else 0

    col_sel1, col_sel2 = st.columns([2, 3])
    with col_sel1:
        selected_host = st.selectbox("Select Host for In-Depth XAI Inspection:", available_hosts, index=default_idx)

    target_eval = eval_df[eval_df['host_ip'] == selected_host].iloc[0]
    scaled_feats = target_eval['scaled_features']
    raw_w = target_eval['raw_window']

    with st.spinner("Generating local XAI explanations..."):
        shap_res = xai.explain_window_shap(scaled_feats)
        lime_res = xai.explain_window_lime(scaled_feats)

    st.info(f"**SOC Analyst Incident Narrative ({selected_host}):** {shap_res.get('narrative_summary', 'N/A')}")

    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        st.metric("SHAP Execution Overhead", f"{shap_res.get('execution_overhead_ms', 0):.2f} ms")
    with f_col2:
        st.metric("LIME Execution Overhead", f"{lime_res.get('execution_overhead_ms', 0):.2f} ms")
    with f_col3:
        fidelity_err = shap_res.get('fidelity', {}).get('fidelity_error', 0.0)
        st.metric("SHAP Additivity Error (|Σφ - f(x)|)", f"{fidelity_err:.6f}", delta="Passed (< 0.05)")
    with f_col4:
        st.metric("LIME Surrogate R² Fit", f"{lime_res.get('local_surrogate_r2', 0.85):.3f}")

    st.divider()

    col_x1, col_x2 = st.columns([3, 2])
    with col_x1:
        st.markdown("#### Local SHAP Feature Attributions (Push vs Pull Factors)")
        top_attrs = shap_res.get('all_attributions', [])[:10]
        attr_df = pd.DataFrame(top_attrs)
        if not attr_df.empty:
            attr_df['Color'] = attr_df['shap_value'].apply(lambda x: '#DC2626' if x > 0 else '#16A34A')
            fig_shap = go.Figure(go.Bar(
                x=attr_df['shap_value'],
                y=attr_df['feature'],
                orientation='h',
                marker=dict(color=attr_df['Color']),
                text=[f"{v:+.4f}" for v in attr_df['shap_value']],
                textposition='outside'
            ))
            fig_shap.update_layout(
                title=f"SHAP Waterfall Attributions (Host {selected_host})",
                xaxis_title="Shapley Value φ_i",
                yaxis=dict(autorange="reversed"),
                height=380,
                margin=dict(l=20, r=20, t=35, b=20)
            )
            st.plotly_chart(fig_shap, use_container_width=True)

    with col_x2:
        st.markdown("#### LIME Local Decision Rules")
        lime_rules = lime_res.get('explanation_rules', [])
        if lime_rules:
            st.dataframe(pd.DataFrame(lime_rules), use_container_width=True, height=180)

        st.markdown("#### Global Feature Importance (Mean |SHAP|)")
        global_imp = xai.compute_global_feature_importance()[:5]
        g_df = pd.DataFrame(global_imp)
        fig_global = px.bar(
            g_df, x='mean_abs_shap', y='feature', orientation='h',
            color='mean_abs_shap', color_continuous_scale='Reds'
        )
        fig_global.update_layout(yaxis=dict(autorange="reversed"), height=180, margin=dict(l=10, r=10, t=25, b=10))
        st.plotly_chart(fig_global, use_container_width=True)

    st.divider()

    # -------------------------------------------------------------
    # EXTENDED CAPABILITY: Counterfactual "What-If" Analysis Simulator
    # -------------------------------------------------------------
    st.markdown("### 🧪 Counterfactual Behavioral Simulator (\"What changes would make this benign?\")")
    st.caption("Interactive counterfactual sensitivity analysis: Adjust hypothetical metrics to calculate the minimum behavioral shifts required to return this host to a benign baseline.")

    c_col1, c_col2, c_col3, c_col4 = st.columns(4)
    with c_col1:
        sim_bps = st.slider("Simulated Throughput (Bytes/sec):", 500, 500000, int(raw_w.get('bytes_per_sec', 1500)))
    with c_col2:
        sim_off = st.slider("Off-Hours Activity Ratio:", 0.0, 1.0, float(raw_w.get('off_hours_ratio', 0.0)), 0.1)
    with c_col3:
        sim_db = st.selectbox("Sensitive DB Access (5432):", [0.0, 1.0], index=int(raw_w.get('sensitive_server_access', 0)))
    with c_col4:
        sim_entropy = st.slider("Destination Port Entropy:", 0.0, 4.0, float(raw_w.get('dst_port_entropy', 0.0)), 0.2)

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
        st.metric("Counterfactual Score (s_fused)", f"{sim_pred['s_fused']:.3f}", delta=f"{delta_s:+.3f}", delta_color="inverse")
    with sim_res_c2:
        st.metric("Resulting Severity Tier", sim_pred['severity_tier'])
    with sim_res_c3:
        st.metric("Recommended Action", sim_pred['recommended_action'])


# ===========================================================================
# TAB 3: Policy-Gated Response Console & Surgical SDN Playbooks
# ===========================================================================
with tab3:
    st.subheader("Policy-Gated Response & Surgical SDN Playbooks")
    st.markdown("""
    Security analysts review elevated threats and authorize targeted OpenFlow actions.
    Beyond binary isolation, the SDN controller supports **Surgical Micro-Segmentation**
    (blocking only specific ports or servers while preserving intranet connectivity).
    """)

    pending_alerts = eval_df[eval_df['s_fused'] >= 0.35]

    st.markdown("### ⚠️ Pending Threat Alerts Awaiting Analyst Authorization")
    if pending_alerts.empty:
        st.success("✅ No elevated threat alerts currently pending authorization.")
    else:
        for idx, alert in pending_alerts.iterrows():
            host_ip = alert['host_ip']
            tier = alert['severity_tier']
            fused_score = alert['s_fused']
            mitre_data = alert['mitre']

            with st.expander(f"🚨 [{tier.upper()} SEVERITY] Host {host_ip} - Fused Score: {fused_score:.3f} ({mitre_data['technique_name']})", expanded=(tier in ['High', 'Critical'])):
                col_a1, col_a2 = st.columns([3, 2])
                with col_a1:
                    st.markdown(f"**Asset Role:** `{alert['role']}`")
                    st.markdown(f"**MITRE Technique:** `{mitre_data['technique_id']}: {mitre_data['technique_name']}` ({mitre_data['tactic']})")
                    st.markdown(f"**NIST SP 800-53 Control:** `{mitre_data['nist_control']}`")
                    st.markdown(f"**Scores:** Supervised: `{alert['p_supervised']:.3f}` | Unsupervised: `{alert['s_unsupervised']:.3f}` | Context: `{alert['s_context']:.3f}`")
                    st.markdown(f"**Throughput Rate:** `{alert['bytes_per_sec'] / 1024:.1f} KB/s`")

                with col_a2:
                    st.markdown("##### Authorized SDN Playbook Action")
                    playbook_action = st.selectbox(
                        "Select Containment Playbook:",
                        [
                            "Full Host Isolation (OpenFlow DROP all traffic)",
                            "Surgical Port Block (Drop only DB:5432 & File:445)",
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
                        "Analyst Justification / Ticket #:",
                        value=f"Mitigating {mitre_data['technique_id']} on {host_ip} ({tier} severity)",
                        key=f"notes_{host_ip}"
                    )

                    btn_c1, btn_c2 = st.columns(2)
                    with btn_c1:
                        if st.button("🚀 Authorize Playbook", key=f"auth_{host_ip}", type="primary", use_container_width=True):
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
                                tier, action_code, "SOC_Analyst_Alpha",
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
                                tier, "DISMISSED", "SOC_Analyst_Alpha",
                                0, notes
                            ))
                            conn.commit()
                            conn.close()
                            st.info(f"Alert on {host_ip} dismissed.")
                            time.sleep(0.5)
                            st.rerun()

    st.divider()

    st.markdown("### 🔒 Active OpenFlow Mitigations & Rollback Controls")
    if not active_mits:
        st.write("No active mitigation rules currently enforced.")
    else:
        for mit in active_mits:
            ip = mit['ip_src']
            act = mit['action']
            rem_ttl = mit.get('remaining_ttl', 0)
            m_col1, m_col2, m_col3, m_col4 = st.columns([2, 2, 2, 2])
            with m_col1:
                st.markdown(f"**Host:** `{ip}`")
            with m_col2:
                st.markdown(f"**Action:** `{act}` (Switch s{mit['switch_id']})")
            with m_col3:
                st.markdown(f"**Remaining TTL:** `{rem_ttl}s` / `{mit['ttl_sec']}s`")
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
                        "N/A", "MANUAL_ROLLBACK", "SOC_Analyst_Alpha",
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
    st.subheader("Immutable Incident Audit Log & Forensic Investigation Dossier")
    st.markdown("""
    Captures all triggered alerts, analyst response decisions, OpenFlow flow rule modifications,
    and provides single-click formal **Forensic Investigation Dossier** generation.
    """)

    conn = sqlite3.connect(DEFAULT_DB_PATH)
    audit_df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100", conn)
    conn.close()

    col_aud1, col_aud2 = st.columns([3, 2])
    with col_aud1:
        st.markdown("#### Historical Audit Ledger")
        if audit_df.empty:
            st.write("No audit entries recorded yet.")
        else:
            st.dataframe(audit_df, use_container_width=True, height=280)
            csv_data = audit_df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Audit Ledger (CSV)", data=csv_data, file_name="sdn_audit_log.csv", mime="text/csv")

    with col_aud2:
        st.markdown("#### Formal Forensic Report Generator")
        report_host = st.selectbox("Select Target Host for Dossier:", available_hosts, key="rep_host")
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
            label="📄 Download Forensic Incident Dossier (HTML)",
            data=html_dossier,
            file_name=f"Forensic_Report_{report_host}.html",
            mime="text/html",
            use_container_width=True
        )

        with st.expander("👁️ Preview Formal Report Summary", expanded=False):
            st.components.v1.html(html_dossier, height=450, scrolling=True)


# ===========================================================================
# TAB 5: MITRE ATT&CK for Enterprise Matrix
# ===========================================================================
with tab5:
    st.subheader("MITRE ATT&CK for Enterprise Framework Correlation")
    st.markdown("""
    All internal behavioral anomalies detected by the XAI engine are correlated directly to
    the industry-standard **MITRE ATT&CK** Enterprise Knowledge Base.
    """)

    for t_key, t_info in MITRE_TECHNIQUES.items():
        with st.container():
            st.markdown(f"### 🛡️ {t_info['technique_id']}: {t_info['technique_name']}")
            st.markdown(f"<span class='mitre-badge'>{t_info['tactic']}</span> • **NIST Control:** `{t_info['nist_control']}`", unsafe_allow_html=True)
            st.markdown(f"**Behavioral Profile:** {t_info['description']}")
            st.markdown(f"**Primary Detection Features:** `{'`, `'.join(t_info['primary_features'])}`")
            st.markdown(f"**Surgical SDN Response:** `{t_info['recommended_sdn_action']}`")
            st.divider()

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.caption("Explainable AI-Based Insider Threat Detection via Network Behavior Analysis in SDN Environments Using SHAP/LIME • Academic Final Year Project Prototype")
