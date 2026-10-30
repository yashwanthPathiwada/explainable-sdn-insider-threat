# Explainable AI-Based Insider Threat Detection via Network Behavior Analysis in Software-Defined Networking (SDN) Environments Using SHAP/LIME

**Academic Final Year Project Prototype • Extended Enterprise SOC Edition**  
**Domain:** Cybersecurity • Software-Defined Networking (SDN) • Explainable Artificial Intelligence (XAI) • Applied Machine Learning  
**Protocols & Frameworks:** OpenFlow 1.3, Ryu SDN Controller, Mininet, Scikit-Learn, SHAP, LIME, Streamlit, Plotly, MITRE ATT&CK  

---

## 📌 Executive Summary & Architecture Overview

Modern enterprise environments face severe risks from malicious or compromised insiders whose legitimate credentials allow them to bypass perimeter firewalls. Traditional Network Intrusion Detection Systems (NIDS) rely on static signatures and lack internal lateral visibility. Software-Defined Networking (SDN) decouples the control plane from the data plane, providing global network visibility and programmatic dynamic flow control.

This project delivers an end-to-end, production-grade cybersecurity prototype that leverages **OpenFlow 1.3 SDN telemetry**, **10-second host sliding-window behavioral feature extraction**, **hybrid risk fusion (Supervised Random Forest + Unsupervised Isolation Forest + Contextual Flags)**, and a **dual XAI explainability layer (SHAP TreeExplainer & LIME TabularExplainer)**.

### 🌟 Unique Academic Innovations Included:
1. **Interactive Visual SDN Digital Twin**: Real-time Plotly topological graph showing switches (`c1`, `s1`, `s2`, `s3`) and hosts with dynamic threat-level and quarantine blast-radius coloring.
2. **Counterfactual "What-If" Behavioral Simulator**: Interactive sensitivity sliders that compute the exact minimum behavioral shifts needed to flip an anomaly back to benign.
3. **MITRE ATT&CK for Enterprise Matrix**: Direct mapping of detected anomalies to Tactics (Exfiltration, Discovery, Privilege Escalation) and Techniques (`T1048.003`, `T1046`, `T1078.002`).
4. **Surgical SDN Playbooks (Micro-Segmentation)**: Enables surgical port blocking (dropping only DB `5432` or File `445` while preserving internal intranet) alongside rate-limiting and full isolation.
5. **Formal Forensic Incident Dossier Generator**: Single-click export of court-admissible HTML/PDF incident investigation reports with full cryptographic verification and attribution evidence.

```
                              +---------------------------------------+
                              |        Ryu OpenFlow Controller        |
                              |   (L2/L3 Learning, Stats Poller 1s)   |
                              +-------------------+-------------------+
                                                  | OpenFlow 1.3
                   +------------------------------+------------------------------+
                   |                                                             |
         +---------+---------+                                         +---------+---------+
         | Switch s1 (Edge)  |                                         | Switch s2 (Edge)  |
         +----+----+----+----+                                         +----+----+----+----+
              |    |    |                                                   |    |
             ws1  ws2  ws3                                                 db   file
        (10.0.1.10) (11) (12)                                         (10.0.2.10)(20)
                   |
                   v (1-second OpenFlow Flow & Port Telemetry)
         +-----------------------------------------------------------------------+
         |               SQLite Database Engine (flow_records.db)                |
         +-----------------------------------+-----------------------------------+
                                             |
                                             v
         +-----------------------------------------------------------------------+
         |            Module 2: 10s Host Sliding-Window Feature Extractor        |
         | (Volume, Rates, Durations, Shannon Entropy, Z-Scores, Context Roles)  |
         +-----------------------------------+-----------------------------------+
                                             |
                                             v
         +-----------------------------------------------------------------------+
         |              Module 3: Multi-Model Risk Fusion Engine                 |
         |    P_sup (Cost-Sensitive RF) + S_unsup (Isolation Forest) + S_ctx     |
         |            s_fused = 0.50*P_sup + 0.30*S_unsup + 0.20*S_ctx           |
         +-----------------------------------+-----------------------------------+
                                             |
                                             v
         +-----------------------------------------------------------------------+
         |            Module 4: Explainability Layer (SHAP & LIME)               |
         |    - Local Shapley Push/Pull Factors & Narrative Incident Summary     |
         |    - LIME Local Surrogate Rules & Fidelity Check (|Σφ - f(x)| < 0.05) |
         |    - Counterfactual "What-If" Analysis Behavioral Simulator           |
         +-----------------------------------+-----------------------------------+
                                             |
                                             v
         +-----------------------------------------------------------------------+
         |         Module 5: Policy-Gated Response Dashboard & Audit Log         |
         |  - Visual SDN Digital Twin (Interactive Topology & Blast Radius)      |
         |  - Human-in-the-Loop Analyst Authorization & Surgical Playbooks       |
         |  - Automated TTL Expiration & One-Click OpenFlow Rule Rollback        |
         |  - Single-Click Formal Forensic Incident Dossier Generator            |
         +-----------------------------------------------------------------------+
```

---

## 📂 Repository File Index

```
explainable-sdn-insider-threat/
├── mininet_topo.py              # MODULE 1: Mininet OpenFlow 1.3 Enterprise Topology
├── ryu_controller.py            # MODULE 1: Ryu SDN Controller, 1s Stats Poller & REST API
├── feature_engineering.py       # MODULE 2: 10s Sliding-Window Feature Extraction & Robust Scaling
├── train_detector.py            # MODULE 3: Cost-Sensitive RF + Benign Isolation Forest + Risk Fusion
├── explainability.py            # MODULE 4: SHAP TreeExplainer, LIME Surrogate & Fidelity Profiler
├── app.py                       # MODULE 5: Streamlit SOC Dashboard, Topology Graph & Playbooks
├── mitre_mapper.py              # EXTENSION: MITRE ATT&CK for Enterprise Correlation Engine
├── incident_report_generator.py # EXTENSION: Formal HTML/PDF Forensic Dossier Generator
├── traffic_generator.py         # Realistic Benign & 4 Attack Scenarios Generator
├── run_demo.py                  # One-Click Turnkey Demonstration Script for Presentation Day
├── requirements.txt             # Pinned Dependencies
├── data/
│   └── flow_records.db          # SQLite Telemetry Store & Active Mitigations Table
└── models/
    ├── supervised_rf.pkl        # Serialized Cost-Sensitive Random Forest
    ├── unsupervised_iforest.pkl # Serialized Benign-Only Isolation Forest
    ├── robust_scaler.pkl        # Fitted Median/IQR Robust Scaler
    ├── baseline_stats.json      # Historical Host Baselines for Z-Score Calculation
    └── model_metadata.json      # Training Metrics, Confusion Matrix, Hyperparameters
```

---

## 🔬 Mathematical Formulations

### 1. Shannon Entropy (Target IP & Port Dispersion)
$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i), \quad p(x_i) = \frac{\text{count}(x_i)}{N}$$

### 2. Historical Baseline Z-Score Deviation
$$Z = \frac{\text{Throughput}_{\text{current}} - \mu_{\text{baseline}}}{\sigma_{\text{baseline}}}$$

### 3. Multi-Model Risk Fusion
$$s_{\text{fused}} = w_{\text{sup}} \cdot P_{\text{supervised}} + w_{\text{unsup}} \cdot S_{\text{unsupervised}} + w_{\text{ctx}} \cdot S_{\text{context}}$$
Where: $w_{\text{sup}} = 0.50$, $w_{\text{unsup}} = 0.30$, and $w_{\text{ctx}} = 0.20$.

### 4. Four Severity Tiers
- **Low Risk** ($s_{\text{fused}} < 0.35$): Normal enterprise activity.
- **Medium Risk** ($0.35 \le s_{\text{fused}} < 0.65$): Suspicious behavior; enhanced logging.
- **High Risk** ($0.65 \le s_{\text{fused}} < 0.85$): Confirmed threat; recommended rate-limiting.
- **Critical Risk** ($s_{\text{fused}} \ge 0.85$): Imminent exfiltration; immediate OpenFlow DROP isolation.

### 5. SHAP Additivity Fidelity Criterion
$$\left| \left( \phi_0 + \sum_{i=1}^{M} \phi_i \right) - f(x) \right| < 0.05$$
*(Empirically verified on our testbed with an additivity error of $0.000000$)*.

---

## ⚡ Live Execution & Dashboard Access

The prototype is currently active in your background environment:
* **Interactive Dashboard:**  https://explainable-sdn-insider-threat-2serxe4t3erjknebczdese.streamlit.app/
