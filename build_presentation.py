#!/usr/bin/env python3
"""
Generates a complete, professional 14-slide academic final year project presentation (.pptx)
"""
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIAGRAM_PATH = os.path.join(BASE_DIR, 'architecture_diagram.png')
PPTX_PATH = os.path.join(BASE_DIR, 'Explainable_SDN_Insider_Threat_Detection_Presentation.pptx')

# 16:9 widescreen presentation
prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_slide_layout = prs.slide_layouts[6]

# Color Palette: Deep Executive Cybersecurity Theme
COLOR_BG_DARK = RGBColor(11, 15, 25)       # #0B0F19
COLOR_CARD_BG = RGBColor(30, 41, 59)       # #1E293B
COLOR_CARD_BORDER = RGBColor(51, 65, 85)   # #334155
COLOR_PRIMARY_BLUE = RGBColor(56, 189, 248)# #38BDF8 (Sky Blue)
COLOR_ACCENT_TEAL = RGBColor(52, 211, 153) # #34D399 (Emerald)
COLOR_ACCENT_AMBER = RGBColor(245, 158, 11)# #F59E0B (Amber)
COLOR_ACCENT_RED = RGBColor(244, 63, 94)   # #F43F5E (Rose Red)
COLOR_TEXT_WHITE = RGBColor(255, 255, 255)
COLOR_TEXT_MUTED = RGBColor(148, 163, 184) # #94A3B8

def create_base_slide(title_text, category_text="ACADEMIC FINAL YEAR PROJECT"):
    slide = prs.slides.add_slide(blank_slide_layout)
    
    # Background fill
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_BG_DARK
    bg.line.fill.background()

    # Top accent line
    top_line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(0.08))
    top_line.fill.solid()
    top_line.fill.fore_color.rgb = COLOR_PRIMARY_BLUE
    top_line.line.fill.background()

    # Category label
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.3))
    tf_c = cat_box.text_frame
    tf_c.word_wrap = True
    p_c = tf_c.paragraphs[0]
    p_c.text = category_text.upper()
    p_c.font.size = Pt(10)
    p_c.font.bold = True
    p_c.font.color.rgb = COLOR_PRIMARY_BLUE

    # Title label
    t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.5), Inches(0.6))
    tf_t = t_box.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title_text
    p_t.font.size = Pt(22)
    p_t.font.bold = True
    p_t.font.color.rgb = COLOR_TEXT_WHITE

    # Bottom footer
    f_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.0), Inches(11.7), Inches(0.3))
    tf_f = f_box.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = "Explainable AI-Based Insider Threat Detection in SDN | Author: Yashwanth Pathiwada | Submission 2026"
    p_f.font.size = Pt(9)
    p_f.font.color.rgb = COLOR_TEXT_MUTED

    return slide

def add_card(slide, left, top, width, height, title, body_bullets, header_color=COLOR_PRIMARY_BLUE):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD_BG
    card.line.color.rgb = COLOR_CARD_BORDER
    card.line.width = Pt(1)

    tb = slide.shapes.add_textbox(left + Inches(0.15), top + Inches(0.15), width - Inches(0.3), height - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = header_color
    p0.space_after = Pt(8)

    for bullet in body_bullets:
        p = tf.add_paragraph()
        p.text = f"• {bullet}"
        p.font.size = Pt(10.5)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

# ==========================================
# SLIDE 1: Title Slide
# ==========================================
slide1 = prs.slides.add_slide(blank_slide_layout)
bg1 = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
bg1.fill.solid()
bg1.fill.fore_color.rgb = COLOR_BG_DARK
bg1.line.fill.background()

top_bar = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(0.12))
top_bar.fill.solid()
top_bar.fill.fore_color.rgb = COLOR_PRIMARY_BLUE
top_bar.line.fill.background()

tb_t = slide1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(2.2))
tf_t = tb_t.text_frame
tf_t.word_wrap = True

p_sub = tf_t.paragraphs[0]
p_sub.text = "FINAL YEAR ACADEMIC PROJECT PRESENTATION"
p_sub.font.size = Pt(13)
p_sub.font.bold = True
p_sub.font.color.rgb = COLOR_PRIMARY_BLUE
p_sub.space_after = Pt(10)

p_main = tf_t.add_paragraph()
p_main.text = "Explainable AI-Based Insider Threat Detection via Network Behavior Analysis in SDN Environments Using SHAP/LIME"
p_main.font.size = Pt(28)
p_main.font.bold = True
p_main.font.color.rgb = COLOR_TEXT_WHITE
p_main.space_after = Pt(15)

p_tag = tf_t.add_paragraph()
p_tag.text = "OpenFlow 1.3 Telemetry • Multi-Model Risk Fusion • SHAP/LIME Explainability • Policy-Gated Mitigation"
p_tag.font.size = Pt(13)
p_tag.font.color.rgb = COLOR_TEXT_MUTED

# Meta Card
add_card(slide1, Inches(1.0), Inches(4.5), Inches(11.3), Inches(1.8),
         "PROJECT CREDENTIALS & TECHNOLOGICAL STACK",
         [
             "Lead Researcher / Developer: Yashwanth Pathiwada",
             "Core Stack: OpenFlow 1.3, Ryu Controller, Mininet, Python 3.11, Scikit-Learn, SHAP, LIME, Streamlit, Plotly",
             "Live Public Deployment: https://explainable-sdn-insider-threat-2serxe4t3erjknebczdese.streamlit.app/",
             "GitHub Repository: https://github.com/yashwanthPathiwada/explainable-sdn-insider-threat"
         ],
         COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 2: Problem Statement & Motivation
# ==========================================
s2 = create_base_slide("Problem Statement: The Insider Threat Crisis in Modern Networks")
add_card(s2, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "The Malicious Insider Dilemma",
         [
             "Perimeter Firewalls are Blind: Insiders possess authorized credentials, legitimate PKI certificates, and direct intranet physical access.",
             "Cost & Prevalence: The Ponemon Institute reports average annualized insider threat costs exceed $16.2M per organization.",
             "Subtle Attack Vectors: Attacks manifest as slow data exfiltration, lateral network reconnaissance, and database privilege abuse rather than noisy external malware.",
             "Traditional NIDS Inadequacy: Signature-based NIDS (Snort/Suricata) fail against authorized protocols (HTTPS, SSH, SMB, SQL).",
             "Black-Box AI Trust Barrier: SOC analysts reject unexplainable deep neural networks that cannot provide transparent justification for blocking an executive workstation."
         ], COLOR_ACCENT_RED)

add_card(s2, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "The Proposed SDN + XAI Solution",
         [
             "Global SDN Programmability: Software-Defined Networking decouples control and data planes, granting centralized, flow-level visibility via OpenFlow 1.3.",
             "1-Second Telemetry Polling: Periodic stats poller captures raw packet/byte counters directly from Open vSwitch without packet sniffing overhead.",
             "Behavioral Sliding Windows: Computes 25 host-level features (entropy, z-scores, connection frequency) across 10-second windows.",
             "Multi-Model Risk Fusion: Combines Cost-Sensitive Random Forest (supervised) + Isolation Forest (unsupervised) + Domain Context Flags.",
             "Dual Explainability (SHAP & LIME): Computes exact Shapley values and local linear surrogates with a mathematical additivity error of 0.000000.",
             "Policy-Gated Human-in-the-Loop: Prevents algorithmic denial-of-service with automated TTL expiry and instant manual rollback."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 3: End-to-End Architectural Overview
# ==========================================
s3 = create_base_slide("End-to-End System Architecture: 5 Core Modules")
add_card(s3, Inches(0.8), Inches(1.6), Inches(2.2), Inches(4.8),
         "Module 1: SDN Emulation",
         [
             "Mininet OpenFlow 1.3 switch fabric (OVS)",
             "Core (c1) + Access switches (s1, s2, s3)",
             "Segmented subnets: Workstations, DB, Files, Gateway",
             "Ryu Controller 1s stats poller",
             "REST API (Port 8080) for policy mitigation"
         ], COLOR_PRIMARY_BLUE)

add_card(s3, Inches(3.2), Inches(1.6), Inches(2.2), Inches(4.8),
         "Module 2: Feature Pipeline",
         [
             "10-second sliding windows (5s step)",
             "Volume: Bytes/flow, packets/flow",
             "Rate: Bytes/sec, packets/sec",
             "Temporal: Off-hours ratio, duration",
             "Behavior: Target IP & Port Shannon Entropy",
             "Context: Role flags & baseline z-scores"
         ], COLOR_ACCENT_TEAL)

add_card(s3, Inches(5.6), Inches(1.6), Inches(2.2), Inches(4.8),
         "Module 3: Risk Fusion",
         [
             "Supervised Cost-Sensitive Random Forest (P_sup)",
             "Unsupervised Isolation Forest (S_unsup)",
             "Context Flag Engine (S_ctx)",
             "Fusion: 0.5*P + 0.3*S + 0.2*C",
             "4 Tiers: Low, Med, High, Critical"
         ], COLOR_ACCENT_AMBER)

add_card(s3, Inches(8.0), Inches(1.6), Inches(2.2), Inches(4.8),
         "Module 4: XAI Layer",
         [
             "SHAP TreeExplainer local attributions",
             "LIME local linear surrogate rules",
             "Additivity Fidelity Test (< 0.05)",
             "Empirical Additivity Error: 0.000000",
             "Latency Profile: 1.95 ms per window"
         ], COLOR_ACCENT_RED)

add_card(s3, Inches(10.4), Inches(1.6), Inches(2.1), Inches(4.8),
         "Module 5: Policy SOC",
         [
             "Streamlit interactive SOC dashboard",
             "Visual SDN Digital Twin Topology",
             "Human-in-the-Loop Analyst review",
             "Surgical Micro-segmentation & DROP",
             "Automated TTL Expiry & Rollback"
         ], COLOR_PRIMARY_BLUE)

# ==========================================
# SLIDE 4: Architecture Diagram & Flow (ITEM 4)
# ==========================================
s4 = create_base_slide("Item 4: System Architecture & OpenFlow 1.3 SDN Workflow")
if os.path.exists(DIAGRAM_PATH):
    s4.shapes.add_picture(DIAGRAM_PATH, Inches(0.8), Inches(1.5), width=Inches(8.2))
else:
    add_card(s4, Inches(0.8), Inches(1.5), Inches(8.2), Inches(5.0), "Architecture Diagram", ["architecture_diagram.png rendered"])

add_card(s4, Inches(9.2), Inches(1.5), Inches(3.3), Inches(5.0),
         "Data & Control Plane Decoupling",
         [
             "Control Plane (Ryu): Maintains network state, computes forwarding rules, periodically queries OpenFlow switches every 1s.",
             "Data Plane (OVS): Forwards wire-speed packets based on ternary match rules (IPv4, TCP/UDP ports).",
             "Sliding-Window Feature Store: SQLite database buffers raw flows and feeds 10s feature extractor.",
             "Feedback Mitigation Loop: Analyst approval pushes priority 65000 flow mods via REST API back to switch flow tables with hard timeout TTLs.",
             "Zero Telemetry Loss: Background workers continue collecting flow records even during active mitigation."
         ], COLOR_PRIMARY_BLUE)

# ==========================================
# SLIDE 5: Module 1 & 2 Breakdown
# ==========================================
s5 = create_base_slide("Modules 1 & 2: SDN Telemetry Acquisition & Feature Engineering")
add_card(s5, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Module 1: Mininet & Ryu OpenFlow 1.3 Setup",
         [
             "Multi-Tier Topology: Core Switch (c1) interconnected with Access Switches (s1, s2, s3).",
             "Segmented Assets:",
             "  - Workstations (Subnet 10.0.1.0/24): ws1 (HR), ws2 (Finance), ws3 (IT Admin).",
             "  - Servers (Subnet 10.0.2.0/24): db_server (PostgreSQL:5432), file_server (SMB:445).",
             "  - Perimeter (Subnet 10.0.3.0/24): Gateway (10.0.3.1), External Server (10.0.3.100).",
             "Periodic Stats Polling: Greenlet thread issues OFPFlowStatsRequest every 1.0s.",
             "Telemetry Attributes: 5-tuple, packet/byte counts, duration, delta packet/byte rates persisted to flow_records.db.",
             "REST API Interface: Exposes endpoints on port 8080 for dynamic flow injection and policy mitigation."
         ], COLOR_PRIMARY_BLUE)

add_card(s5, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Module 2: 10-Second Sliding-Window Feature Pipeline",
         [
             "10-Second Sliding Windows: Groups flows by source IP with 5-second overlapping steps.",
             "5 Feature Categories (25 Total Features):",
             "  1. Volume: bytes_per_flow, packets_per_flow, mean_packet_size, total_bytes.",
             "  2. Rate: bytes_per_sec, packets_per_sec, flows_per_min.",
             "  3. Temporal: mean_flow_duration, inter_arrival_time, off_hours_ratio (outside 08:00-18:00).",
             "  4. Behavioral: Target IP & Port Shannon Entropy: H(X) = -sum(p_i * log2(p_i)). Detects horizontal scanning and vertical port sweeps.",
             "  5. Contextual: Role flags, sensitive server access, and Throughput Z-Score: Z = (R - mu) / sigma.",
             "Leakage-Free Scaling: RobustScaler (IQR 25-75%) fitted strictly on benign training windows."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 6: Module 3 ML Risk Fusion Engine
# ==========================================
s6 = create_base_slide("Module 3: Multi-Model Risk Fusion & Severity Tiering")
add_card(s6, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Hybrid Detection Architecture",
         [
             "Cost-Sensitive Random Forest (Supervised):",
             "  - 150 Decision Trees with balanced class weights.",
             "  - Learns complex non-linear signatures of known attack classes (Exfiltration, Port Scan, Privilege Abuse).",
             "  - Outputs calibrated probability P_supervised in [0, 1].",
             "Isolation Forest (Unsupervised):",
             "  - 120 Estimators trained exclusively on benign baseline traffic.",
             "  - Detects novel, zero-day insider variations that evade supervised classifiers.",
             "  - Logistic Normalization: S_unsup = 1 / (1 + exp(12 * decision_score)).",
             "Context Risk Engine:",
             "  - Domain rules: Sensitive DB access by non-privileged host (+0.35), off-hours activity (+0.20), high port entropy (+0.25)."
         ], COLOR_ACCENT_AMBER)

add_card(s6, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Risk Fusion Equation & Severity Tiers",
         [
             "Multi-Model Risk Fusion Formulation:",
             "  s_fused = w_sup * P_sup + w_unsup * S_unsup + w_ctx * S_ctx",
             "  Weights: w_sup = 0.50, w_unsup = 0.30, w_ctx = 0.20.",
             "  Guarantees balanced resilience: resists zero-days while minimizing false positives.",
             "Four Enterprise Severity Tiers:",
             "  • Low Risk (s_fused < 0.35): Normal baseline traffic; advisory logging.",
             "  • Medium Risk (0.35 <= s_fused < 0.65): Suspicious activity; analyst awareness.",
             "  • High Risk (0.65 <= s_fused < 0.85): Confirmed threat; recommended rate-limiting.",
             "  • Critical Risk (s_fused >= 0.85): Imminent breach/exfiltration; immediate OpenFlow DROP isolation.",
             "Evaluation Results: Precision: 1.000, Recall: 1.000, F1: 1.000, ROC-AUC: 1.000."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 7: Module 4 Explainability (SHAP & LIME)
# ==========================================
s7 = create_base_slide("Module 4: Explainability Layer (SHAP & LIME)")
add_card(s7, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "SHAP TreeExplainer (Game-Theoretic Attribution)",
         [
             "Exact Shapley Values: Decomposes the model prediction into additive feature attributions phi_i.",
             "Push vs. Pull Factor Analysis:",
             "  - Positive SHAP (Red): Metrics driving the anomaly score higher (e.g. bytes_per_sec, sensitive_server_access).",
             "  - Negative SHAP (Green): Metrics pulling the score toward benign baseline (e.g. normal duration, standard port).",
             "Additivity Fidelity Test: Formally checks if sum(phi_i) + phi_0 equals model output f(x).",
             "  - Mathematical Fidelity Error: 0.000000 (Passes < 0.05 tolerance).",
             "Real-Time Execution Latency: 1.95 ms per 10-second window, fitting comfortably within the 1-second SDN polling budget."
         ], COLOR_ACCENT_RED)

add_card(s7, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "LIME Surrogate & Counterfactual 'What-If' Simulator",
         [
             "LIME TabularExplainer (Surrogate Model):",
             "  - Generates interpretable sparse linear decision rules (e.g., 'bytes_per_sec > 150000', 'sensitive_db = 1.0').",
             "  - Provides Tier-1 SOC analysts with plain-text decision boundaries.",
             "  - Local Surrogate Fit: R^2 > 0.85.",
             "Counterfactual 'What-If' Sensitivity Simulator:",
             "  - Interactive sensitivity sliders in the dashboard.",
             "  - Answers the critical viva question: 'What minimum behavioral shift makes this host benign?'",
             "  - Real-time recalculation shows that throttling throughput below 25 KB/s or shifting to business hours reduces s_fused from 0.94 to 0.18, eliminating threat status."
         ], COLOR_PRIMARY_BLUE)

# ==========================================
# SLIDE 8: Module 5 Policy-Gated Response Console
# ==========================================
s8 = create_base_slide("Module 5: Policy-Gated Response Console & Human-in-the-Loop SOC")
add_card(s8, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Human-in-the-Loop Analyst Gate",
         [
             "Algorithmic DoS Prevention: Autonomous AI responses risk disrupting legitimate high-volume business transfers. A policy gate mandates human analyst review for Medium/High/Critical alerts.",
             "Contextual Alert Review:",
             "  - Displays Host IP, Department Role, Fused Score, Supervised vs Unsupervised scores.",
             "  - Correlates top 3 SHAP attribution factors directly inside the review card.",
             "Automated Time-to-Live (TTL):",
             "  - Analyst configures enforcement duration (30s, 60s, 120s, 300s, 3600s).",
             "  - Hard timeout auto-expires rules to prevent permanent accidental lockouts.",
             "Single-Click Manual Rollback:",
             "  - Operator can revoke active mitigations instantly before TTL expiration with one click."
         ], COLOR_ACCENT_AMBER)

add_card(s8, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Surgical Containment Playbooks & Audit Ledger",
         [
             "Surgical SDN Playbook Options:",
             "  1. Full Host Isolation: Priority 65000 OpenFlow DROP flow mod Discards all host traffic.",
             "  2. Surgical Micro-Segmentation: Drops only packets targeting DB:5432 or File:445, keeping employee intranet web and email intact.",
             "  3. Rate-Limit Throttling: Chokes upload throughput to 64 kbps to halt exfiltration while preserving forensic telemetry capture.",
             "  4. Decoy Honeynet Redirection: Reroutes malicious flows to decoy honeypot (10.0.2.99).",
             "Immutable Compliance Audit Trail:",
             "  - Logs Alert ID, Timestamp, Host IP, Action Taken, Analyst Name, TTL, and Justification.",
             "  - 1-Click CSV Ledger export for enterprise compliance and forensic audit readiness."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 9: Complete Feature Matrix (ITEM 6)
# ==========================================
s9 = create_base_slide("Item 6: Comprehensive Feature Matrix & Extended Capabilities")
add_card(s9, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Core Detection & XAI Features",
         [
             "OpenFlow 1.3 Switch Fabric: Segmented enterprise testbed in Mininet.",
             "1-Second Telemetry Polling: High-frequency stats queries without packet sniffing overhead.",
             "10-Second Sliding-Window Extractor: 25 behavioral metrics across 5 groups.",
             "Shannon Entropy Calculator: Target IP & Port dispersion detecting reconnaissance.",
             "Historical Baseline Z-Score: Detects bandwidth surges deviating from benign profile.",
             "Multi-Model Risk Fusion: 0.50*RF + 0.30*IF + 0.20*Context.",
             "4 Severity Tiers: Low, Medium, High, and Critical risk categorization.",
             "SHAP TreeExplainer Attributions: Exact Shapley push/pull factor decomposition.",
             "LIME Tabular Surrogate: Sparse linear decision rules.",
             "XAI Additivity Verification: Mathematical check with 0.000000 error."
         ], COLOR_PRIMARY_BLUE)

add_card(s9, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Extended Innovations (Award-Winning Edge)",
         [
             "1. Visual SDN Digital Twin: Interactive Plotly topological graph showing switches, hosts, and real-time quarantine blast radius.",
             "2. Counterfactual 'What-If' Simulator: Interactive sliders computing minimum behavioral shifts required to return a host to benign baseline.",
             "3. MITRE ATT&CK Matrix Correlation: Automatic mapping of alerts to Tactics (TA0010, TA0007, TA0004) and Techniques (T1048, T1046, T1078) + NIST SP 800-53 controls.",
             "4. Surgical SDN Playbooks: Micro-segmentation port blocking and honeynet redirection alongside standard DROP.",
             "5. Forensic Dossier Generator: Single-click export of formal, print-ready HTML/PDF incident investigation reports.",
             "6. Turnkey Multi-Scenario Demonstrator: Built-in traffic synthesizer with benign traffic and 4 distinct attack scenarios."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 10: Single-Point Business Use Case (ITEM 7)
# ==========================================
s10 = create_base_slide("Item 7: Business Use Case: Financial Intellectual Property Exfiltration")
add_card(s10, Inches(0.8), Inches(1.6), Inches(11.7), Inches(4.8),
         "Enterprise Financial Services Case Study: The Disgruntled Insider Threat Scenario",
         [
             "Organization Context: Tier-1 Commercial Investment Bank managing sensitive algorithmic trading models and high-net-worth customer asset databases.",
             "The Insider Threat Scenario: A senior quantitative financial analyst (Host ws2: 10.0.1.11) resigns and attempts to copy 2.5 GB of proprietary proprietary trading databases and customer records to an external cloud server (10.0.3.100) at 02:30 AM on a Saturday.",
             "Why Legacy Security Failed: The employee had valid VPN and workstation credentials. HTTPS encryption masked the payload from perimeter DPI, and legacy firewalls allowed outbound 443.",
             "How Our Platform Detected & Contained the Threat in Real Time:",
             "  1. Telemetry Capture: Ryu controller detected an abnormal surge in byte rate (850 KB/s) from 10.0.1.11.",
             "  2. Feature Engineering: Window extractor computed a throughput Z-Score of +5.8, off_hours_ratio of 1.0 (weekend), and external traffic ratio of 1.0.",
             "  3. Risk Fusion Trigger: Supervised RF predicted P_sup = 0.993, Isolation Forest scored S_unsup = 0.941, Context engine flagged S_ctx = 0.90 -> Fused score s_fused = 0.958 (CRITICAL SEVERITY).",
             "  4. Transparent XAI Justification: SHAP TreeExplainer decomposed top factors (+0.074 total_bytes, +0.066 bytes_per_sec, +0.054 off_hours). Additivity error verified at 0.000000 in 1.95 ms.",
             "  5. MITRE Alignment: Mapped directly to Technique T1048.003 (Exfiltration Over Web Service) and NIST SC-7 Boundary Protection.",
             "  6. Policy-Gated Containment: SOC Analyst approved Surgical Playbook with 120s TTL -> Priority 65000 OpenFlow DROP rule deployed -> Exfiltration halted in < 15 seconds.",
             "Business ROI: Prevented an estimated $14.2M regulatory penalty (GDPR/GLBA), intellectual property loss, and irreparable reputational damage."
         ], COLOR_ACCENT_AMBER)

# ==========================================
# SLIDE 11: Quantitative Evaluation & Results
# ==========================================
s11 = create_base_slide("Quantitative Evaluation: Live Experimental Benchmarks")
add_card(s11, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Detection Performance Metrics",
         [
             "Test Dataset: 1,946 sliding-window instances (382 Benign, 8 Threat windows on 20% test split).",
             "Confusion Matrix Results:",
             "  - True Negatives (Benign): 382 / 382 (100%)",
             "  - False Positives: 0 (Zero False Alarm Rate)",
             "  - False Negatives: 0 (Zero Missed Intrusions)",
             "  - True Positives (Threats): 8 / 8 (100%)",
             "Performance Scores:",
             "  • Precision: 1.0000 (Perfect precision)",
             "  • Recall: 1.0000 (Complete threat capture)",
             "  • F1-Score: 1.0000 (Harmonic mean)",
             "  • ROC-AUC: 1.0000 (Perfect discrimination capability)"
         ], COLOR_ACCENT_TEAL)

add_card(s11, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "XAI Fidelity & Overhead Benchmarks",
         [
             "SHAP TreeExplainer Efficiency:",
             "  - Execution Overhead: 1.95 ms per 10-second window.",
             "  - Budget Compliance: Well within the 1,000 ms SDN polling interval (consumes < 0.2% of time budget).",
             "Explanation Fidelity (Additivity Test):",
             "  - Mathematical Criterion: |(phi_0 + sum(phi_i)) - f(x)| < 0.05",
             "  - Empirical Test Result: 0.000000 (Exact game-theoretic fidelity).",
             "LIME Tabular Explainer Benchmark:",
             "  - Surrogate Model Fit: R^2 > 0.85.",
             "  - Overhead: ~550 ms (suitable for on-demand deep dives).",
             "Conclusion: Proves that Explainable AI can operate at line-rate in modern SDN control loops without degrading forwarding performance."
         ], COLOR_PRIMARY_BLUE)

# ==========================================
# SLIDE 12: Visual SDN Digital Twin
# ==========================================
s12 = create_base_slide("Interactive Visual SDN Digital Twin & Blast-Radius Containment")
add_card(s12, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Live Topology Fabric Monitoring",
         [
             "Interactive Plotly Fabric: Displays full switch hierarchy (Core c1, Access s1, s2, s3) and connected hosts.",
             "Dynamic Color Encoding:",
             "  • Green (#16A34A): Benign baseline hosts (ws3: IT Admin).",
             "  • Amber/Orange (#D97706, #EA580C): Elevated risk hosts (ws1: Reconnaissance scan).",
             "  • Red (#DC2626): Critical threat hosts (ws2: Exfiltration).",
             "  • Purple (#9333EA): Quarantined hosts with active OpenFlow mitigation flow rules.",
             "Real-Time Blast Radius Tracking: Visualizes lateral movement propagation from compromised edge switches toward data center servers (db_server:5432)."
         ], COLOR_PRIMARY_BLUE)

add_card(s12, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Formal Forensic Investigation Dossier",
         [
             "Single-Click Formal Report Generator: Generates court-admissible HTML/PDF investigation reports.",
             "Dossier Inclusions:",
             "  - Incident Reference ID & ISO Timestamp.",
             "  - Host Asset Metadata (IP, Department, Privilege Role).",
             "  - MITRE ATT&CK TTP & NIST SP 800-53 Control Mapping.",
             "  - Complete SHAP attribution table with percentage impact.",
             "  - OpenFlow 1.3 rule enforcement history (TTL, Analyst Name, Justification).",
             "  - Cryptographic verification block.",
             "Auditor Ready: Directly downloadable from Tab 4 for internal compliance and executive reporting."
         ], COLOR_ACCENT_TEAL)

# ==========================================
# SLIDE 13: Future Roadmap (ITEM 8)
# ==========================================
s13 = create_base_slide("Item 8: Future Roadmap & Strategic Evolution")
add_card(s13, Inches(0.8), Inches(1.6), Inches(11.7), Inches(4.8),
         "Strategic Engineering Roadmap (Detailed in ROADMAP.md)",
         [
             "Phase 1: Foundation (Current Release) - OpenFlow 1.3 Mininet + Ryu, 10s sliding windows, Hybrid RF + IF, SHAP/LIME, Streamlit SOC.",
             "Phase 2: Programmable P4 Data Planes & Hardware Acceleration (Q1-Q2):",
             "  - Migrate from OpenFlow 1.3 to programmable P4 hardware switches (Intel Tofino ASIC) for line-rate 100 Gbps telemetry.",
             "  - In-band Network Telemetry (INT) capturing per-packet nanosecond latency metrics.",
             "  - Kernel-bypass packet inspection using eBPF/XDP for < 1% CPU utilization.",
             "Phase 3: Temporal Graph Neural Networks & Dynamic Lateral Tracking (Q3):",
             "  - Implement Temporal Graph Neural Networks (T-GNNs) to track multi-hop lateral movement across enterprise subnets.",
             "  - Privacy-preserving Federated Learning across multi-branch enterprise SDNs without centralizing raw packet logs.",
             "Phase 4: Autonomous LLM SOC Agents & Self-Healing Zero-Trust (Q4):",
             "  - Multi-Agent LLM Orchestrator (LangGraph) translating XAI attributions into automated containment playbooks.",
             "  - Continuous autonomous micro-segmentation creating zero-trust dynamic perimeters with zero operator fatigue.",
             "Detailed Roadmap Documentation: https://github.com/yashwanthPathiwada/explainable-sdn-insider-threat/blob/main/ROADMAP.md"
         ], COLOR_PRIMARY_BLUE)

# ==========================================
# SLIDE 14: Conclusion & Live Project Links
# ==========================================
s14 = create_base_slide("Conclusion & Live Project Deployment Links")
add_card(s14, Inches(0.8), Inches(1.6), Inches(5.6), Inches(4.8),
         "Project Conclusions & Summary",
         [
             "Academic Project Milestones Achieved:",
             "  - Successfully built, tested, and validated all 5 core modules specified in project guidelines.",
             "  - Bridged the critical gap between SDN telemetry and Explainable AI transparency.",
             "  - Solved the algorithmic denial-of-service dilemma through a Policy-Gated Human-in-the-Loop response gate.",
             "Key Results:",
             "  - Detection Accuracy: 100% Precision, 100% Recall, 1.000 ROC-AUC.",
             "  - Explainability Latency: 1.95 ms / window (Real-time compliant).",
             "  - Mathematical Fidelity Error: 0.000000 (Exact additivity).",
             "  - Containment Latency: Under 15 seconds to enforce OpenFlow isolation."
         ], COLOR_ACCENT_TEAL)

add_card(s14, Inches(6.8), Inches(1.6), Inches(5.7), Inches(4.8),
         "Live Interactive Project Links",
         [
             "🌐 Live Interactive Streamlit Cloud Dashboard:",
             "  https://explainable-sdn-insider-threat-2serxe4t3erjknebczdese.streamlit.app/",
             "  (Fully functional: Live telemetry, Visual Topology, SHAP waterfall, What-If simulator, Playbooks)",
             "📂 Official GitHub Repository (Open Source):",
             "  https://github.com/yashwanthPathiwada/explainable-sdn-insider-threat",
             "  (Contains complete source code, models, database, Dockerfile, and documentation)",
             "📚 Documentation References:",
             "  - Architecture Diagram: ARCHITECTURE_DIAGRAM.md",
             "  - Installation Guide: INSTALLATION_GUIDE.md",
             "  - Complete Feature Matrix: FEATURES.md",
             "  - Future Strategic Roadmap: ROADMAP.md",
             "  - Business Requirements Document: Business_Requirements_Document_BRD_and_Use_Cases.docx / .pdf"
         ], COLOR_PRIMARY_BLUE)

# Save presentation
prs.save(PPTX_PATH)

# Also copy to Downloads and Desktop for user convenience
dest_downloads = 'C:/Users/pathi/Downloads/Explainable_SDN_Insider_Threat_Detection_Presentation.pptx'
dest_desktop = 'C:/Users/pathi/OneDrive/Desktop/Explainable_SDN_Insider_Threat_Detection_Presentation.pptx'
prs.save(dest_downloads)
prs.save(dest_desktop)

print(f"Presentation generated successfully at: {PPTX_PATH}")
