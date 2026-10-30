#!/usr/bin/env python3
"""
Generates high-resolution architecture diagram image for the project.
"""
import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

fig, ax = plt.subplots(figsize=(14, 9), dpi=300)
ax.set_xlim(0, 14)
ax.set_ylim(0, 9)
ax.axis('off')

# Background canvas
fig.patch.set_facecolor('#0B0F19')
ax.set_facecolor('#0B0F19')

# Title Header
ax.text(7, 8.5, 'EXPLAINABLE AI-BASED INSIDER THREAT DETECTION IN SDN', 
        fontsize=16, fontweight='bold', color='#38BDF8', ha='center', va='center', fontfamily='sans-serif')
ax.text(7, 8.15, 'OpenFlow 1.3 Telemetry • Multi-Model Risk Fusion • SHAP/LIME Explainability • Policy-Gated Mitigation', 
        fontsize=10, color='#94A3B8', ha='center', va='center', fontfamily='sans-serif')

def draw_box(x, y, w, h, title, subtitle, bg_color, border_color, title_color='#FFFFFF'):
    rect = patches.FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.1,rounding_size=0.15',
                                 facecolor=bg_color, edgecolor=border_color, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h - 0.28, title, fontsize=10, fontweight='bold', color=title_color, ha='center', va='center')
    ax.text(x + w/2, y + h/2 - 0.15, subtitle, fontsize=7.5, color='#CBD5E1', ha='center', va='center', multialignment='center')

# Layer 1: SDN Data Plane (Mininet + OVS)
draw_box(0.5, 5.0, 3.8, 2.5, 'MODULE 1: DATA PLANE', 
         '- Open vSwitch (OVS) OpenFlow 1.3 Fabric\n- Core Switch (c1) + Access (s1, s2, s3)\n- Subnet 1: Workstations (ws1, ws2, ws3)\n- Subnet 2: DB (5432) & File Server (445)\n- Subnet 3: Perimeter Gateway & Ext Server',
         '#1E293B', '#38BDF8', '#38BDF8')

# Layer 2: SDN Control Plane (Ryu Controller)
draw_box(4.9, 5.0, 4.2, 2.5, 'MODULE 1: RYU CONTROLLER',
         '- OpenFlow 1.3 L2/L3 Learning Switch\n- Periodic Stats Poller (every 1.0s)\n- Delta Packet/Byte Rate Calculation\n- Policy Mitigation REST API (Port 8080)\n- Flow Persistence -> flow_records.db',
         '#1E293B', '#818CF8', '#818CF8')

# Telemetry DB & Module 2: Feature Engineering
draw_box(9.7, 5.0, 3.8, 2.5, 'MODULE 2: FEATURE ENGINEERING',
         '- 10-Second Sliding Windows (5s step)\n- 25 Features: Volume, Rate, Temporal\n- Shannon Entropy (Target IP & Port)\n- Host Historical Z-Score Deviation\n- Leakage-Free RobustScaler (IQR)',
         '#1E293B', '#34D399', '#34D399')

# Layer 3: ML Detection & Risk Fusion
draw_box(0.5, 1.2, 3.8, 3.2, 'MODULE 3: ML RISK FUSION',
         '- Supervised Cost-Sensitive RF (P_sup)\n- Unsupervised Isolation Forest (S_unsup)\n- Contextual Domain Flag Engine (S_ctx)\n- Fusion Formula:\n  s_fused = 0.5*P_sup + 0.3*S_unsup + 0.2*S_ctx\n- 4 Severity Tiers (Low/Med/High/Critical)\n- Precision: 1.000 | Recall: 1.000 | F1: 1.000',
         '#1E293B', '#F59E0B', '#F59E0B')

# Layer 4: Explainability Layer (SHAP & LIME)
draw_box(4.9, 1.2, 4.2, 3.2, 'MODULE 4: EXPLAINABILITY (XAI)',
         '- SHAP TreeExplainer:\n  Exact Shapley Values (phi_i) Push/Pull\n  Additivity Error: 0.000000 (|sum(phi) - f(x)| < 0.05)\n  Real-time Latency: 1.95 ms / window\n- LIME TabularExplainer:\n  Local Sparse Linear Surrogate Rules\n- Counterfactual What-If Simulator',
         '#1E293B', '#EC4899', '#EC4899')

# Layer 5: Policy-Gated SOC Dashboard & MITRE
draw_box(9.7, 1.2, 3.8, 3.2, 'MODULE 5: POLICY GATED SOC',
         '- Interactive Streamlit SOC Dashboard\n- Visual SDN Digital Twin Topology\n- Human-in-the-Loop Analyst Gate\n- Surgical Playbooks: DROP / Port Block / Throttle\n- Auto TTL Expiration & One-Click Rollback\n- MITRE ATT&CK: T1048, T1046, T1078\n- 1-Click Forensic Dossier (HTML/PDF)',
         '#1E293B', '#F43F5E', '#F43F5E')

# Arrows connecting components
def draw_arrow(x1, y1, x2, y2, label=''):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color='#38BDF8', lw=2, mutation_scale=15))
    if label:
        ax.text((x1+x2)/2, (y1+y2)/2 + 0.15, label, fontsize=7.5, color='#94A3B8', ha='center', va='bottom')

draw_arrow(4.3, 6.25, 4.9, 6.25, 'OFP 1.3 Stats (1s)')
draw_arrow(9.1, 6.25, 9.7, 6.25, 'Raw Telemetry')
draw_arrow(11.6, 5.0, 11.6, 4.4, '10s Sliding Windows')
draw_arrow(9.7, 2.8, 9.1, 2.8, 'SHAP/LIME Factors')
draw_arrow(4.9, 2.8, 4.3, 2.8, 'Anomaly Vector')
draw_arrow(2.4, 4.4, 2.4, 5.0, 'Model Training')
draw_arrow(9.7, 3.5, 4.9, 6.8, 'REST Mitigation / Rollback (8080)')

plt.tight_layout()

out_path1 = os.path.join(BASE_DIR, 'architecture_diagram.png')
out_path2 = 'C:/Users/pathi/Downloads/explainable-sdn-insider-threat/architecture_diagram.png'

plt.savefig(out_path1, dpi=300, facecolor='#0B0F19')
if os.path.exists(os.path.dirname(out_path2)):
    plt.savefig(out_path2, dpi=300, facecolor='#0B0F19')
print(f"Architecture diagram saved to {out_path1}")
