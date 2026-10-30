# Feature Matrix & Technical Capabilities

Comprehensive catalog of the functional features, analytical models, and extended innovations built into the **Explainable AI-Based Insider Threat Detection in SDN** platform.

---

## 🎯 1. Core Module Capabilities

| Module | Component | Technical Feature | Implementation |
|---|---|---|---|
| **Module 1** | **SDN Emulation** | OpenFlow 1.3 Topology | Custom Mininet script (`mininet_topo.py`) with 4 OVS switches, 3 workstations (`ws1`-`ws3`), 2 sensitive servers (`db_server:5432`, `file_server:445`), and perimeter gateway. |
| **Module 1** | **SDN Controller** | 1-Second Statistics Polling | Ryu application (`ryu_controller.py`) actively sending `OFPFlowStatsRequest` every 1.0s, calculating delta byte/packet rates. |
| **Module 1** | **SDN Controller** | REST API Control | Embedded REST service (port 8080) providing endpoints for mitigation, rollback, flow inspection, and switch status. |
| **Module 2** | **Preprocessing** | 10s Sliding Windows | Partitions raw 5-tuple flow logs into 10-second host sliding windows with 5-second overlapping steps. |
| **Module 2** | **Feature Engineering** | 25 Behavioral Features | Computes 5 distinct feature groups: Volume, Rate, Temporal (off-hours ratio), Behavior (Shannon entropy), and Context (roles, z-scores). |
| **Module 2** | **Scaling** | Robust Preprocessing | Median imputation for missing values + Leakage-free `RobustScaler` fitted strictly on benign training splits. |
| **Module 3** | **Machine Learning** | Supervised RF Classifier | Cost-sensitive Random Forest with balanced class weights to detect known attack signatures despite class imbalance. |
| **Module 3** | **Machine Learning** | Unsupervised Isolation Forest | Outlier detection model trained exclusively on benign traffic, mapping raw scores via logistic transformation for zero-day defense. |
| **Module 3** | **Risk Engine** | Multi-Model Risk Fusion | Mathematical fusion: $s_{\text{fused}} = 0.50 \cdot P_{\text{sup}} + 0.30 \cdot S_{\text{unsup}} + 0.20 \cdot S_{\text{ctx}}$. |
| **Module 3** | **Severity Engine** | 4 Severity Tiers | Low ($< 0.35$), Medium ($0.35 \le s < 0.65$), High ($0.65 \le s < 0.85$), and Critical ($s \ge 0.85$). |
| **Module 4** | **Explainability** | SHAP TreeExplainer | Exact Shapley values ($\phi_i$) for local push/pull factor decomposition and global mean $|SHAP|$ rankings. |
| **Module 4** | **Explainability** | LIME TabularExplainer | Sparse local linear surrogate decision rules explaining non-linear boundaries. |
| **Module 4** | **XAI Validation** | Additivity Fidelity Check | Mathematical additivity verification ($|\sum \phi_i - f(x)| < 0.05$) with empirical error of $0.000000$. |
| **Module 4** | **Profiling** | Latency Profiler | Profiles execution overhead ($1.95\,\text{ms}$ for SHAP TreeExplainer, compliant with real-time SDN control). |
| **Module 5** | **SOC Dashboard** | Real-time Streamlit UI | Live telemetry KPIs, sliding-window trajectory charts, severity pie charts, and host risk matrix. |
| **Module 5** | **Policy Gate** | Human-in-the-Loop Mitigation | Analyst review gate for Medium/High/Critical alerts preventing algorithmic false-positive denial-of-service. |
| **Module 5** | **Policy Gate** | Automated TTL & Rollback | Configurable mitigation Time-to-Live (30s–3600s) with auto-reversion and single-click manual rollback. |
| **Module 5** | **Audit Trail** | Immutable Audit Ledger | SQLite and DataFrame audit log tracking operator decisions, justifications, and rule lifecycles with CSV export. |

---

## 🌟 2. Unique Extended Innovations

### 1. Visual SDN Digital Twin (Interactive Network Topology Graph)
* Interactive Plotly graph rendering the live OpenFlow switch fabric (`c1`, `s1`, `s2`, `s3`) and endpoints.
* **Dynamic Blast Radius Coloring:** Nodes shift dynamically from Green (Benign) to Red (Critical) to **Purple (Quarantined)** in real time when an OpenFlow mitigation is enforced.

### 2. Counterfactual "What-If" Sensitivity Simulator
* Solves the essential XAI problem: *"What minimum behavioral changes would make this host benign?"*
* Interactive sliders for Throughput, Off-Hours Ratio, Database Access, and Port Entropy recalculating $s_{\text{fused}}$ instantly.

### 3. MITRE ATT&CK for Enterprise Matrix Mapping
* Automatic correlation of network anomalies to formal MITRE ATT&CK Tactics and Techniques:
  * **Exfiltration (TA0010):** `T1048.003` (Exfiltration Over Web Protocol)
  * **Discovery (TA0007):** `T1046` (Network Service Discovery / Port Scanning)
  * **Privilege Escalation (TA0004):** `T1078.002` (Valid Accounts: Database / Domain Abuse)
* Mapped directly to federal **NIST SP 800-53** security controls (`SC-7`, `AC-4`, `AC-6`).

### 4. Surgical SDN Micro-Segmentation Playbooks
* Beyond binary host drops, analysts can authorize surgical containment:
  * **Surgical Port Block:** Drops only flows targeting DB `5432` or File Server `445`, keeping employee email/web alive.
  * **Rate-Limit Throttling:** Throttles bandwidth upload to 64 kbps to choke exfiltration while maintaining forensic capture.
  * **Decoy Honeynet Redirection:** Reroutes attacker traffic to a decoy honeypot (`10.0.2.99`).

### 5. Formal Forensic Incident Dossier Generator
* Single-click **"Download Forensic Incident Dossier (HTML)"** creates a court-admissible, print-ready forensic investigation dossier with cryptographic integrity blocks, SHAP tables, and operator sign-offs.

---

## 📊 3. Performance Benchmark Summary

| Metric | Supervised RF | Unsupervised IF | Fused Pipeline ($s_{\text{fused}}$) |
|---|:---:|:---:|:---:|
| **Precision** | 1.0000 | 0.9412 | **1.0000** |
| **Recall** | 1.0000 | 0.9630 | **1.0000** |
| **F1-Score** | 1.0000 | 0.9519 | **1.0000** |
| **ROC-AUC** | 1.0000 | 0.9785 | **1.0000** |
| **SHAP Latency Overhead** | — | — | **1.95 ms / window** |
| **SHAP Additivity Error** | — | — | **0.000000** |
