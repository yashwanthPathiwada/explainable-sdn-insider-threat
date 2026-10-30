# Comprehensive Installation & Deployment Guide

This guide details the complete installation, deployment, and verification procedures for the **Explainable AI-Based Insider Threat Detection in SDN** prototype across multiple target environments.

---

## 💻 1. System Requirements & Prerequisites

| Component | Minimum Requirement | Recommended |
|---|---|---|
| **Operating System** | Windows 10/11, Ubuntu 20.04/22.04 LTS, macOS | Ubuntu 22.04 LTS (for live Mininet) |
| **Python** | Python 3.10 or 3.11 | Python 3.11 |
| **RAM** | 4 GB | 8 GB or 16 GB |
| **Disk Space** | 2 GB free | 5 GB free |
| **Network Tools** | Open vSwitch, Mininet (for SDN mode) | Ryu SDN Controller (v4.34+) |

---

## ⚡ 2. Quick-Start Standalone Mode (Windows / macOS / Linux)

*This mode runs the complete ML detection pipeline, XAI layer (SHAP & LIME), background mitigation REST API, and Streamlit dashboard with pre-populated OpenFlow 1.3 telemetry.*

### Step 1: Clone the Repository
```bash
git clone https://github.com/yashwanthPathiwada/explainable-sdn-insider-threat.git
cd explainable-sdn-insider-threat
```

### Step 2: Set Up Virtual Environment & Dependencies
**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Run the Turnkey Demonstration
```bash
python run_demo.py
```
This automatically initializes the database, verifies the models, starts the REST API on port `8080`, and opens the dashboard at `http://localhost:8501`.

---

## 🐧 3. Full Native SDN Emulation (Mininet + Ryu in Ubuntu Linux)

To run with live OpenFlow 1.3 kernel switches and virtual network namespaces:

### Step 1: Install System Packages
```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-pip git
pip3 install -r requirements.txt
pip3 install ryu
```

### Step 2: Launch the Ryu SDN Controller (Terminal 1)
```bash
ryu-manager --verbose ryu_controller.py
```
*Listens for OpenFlow 1.3 switches on port 6653 and opens the policy mitigation REST API on port 8080.*

### Step 3: Launch Mininet Custom Topology (Terminal 2)
```bash
sudo python3 mininet_topo.py 127.0.0.1 6653
```
*Creates switches `c1`, `s1`, `s2`, `s3`, workstations `ws1`, `ws2`, `ws3`, and servers `db_server`, `file_server`, `ext_srv`.*

### Step 4: Launch the Streamlit Dashboard (Terminal 3)
```bash
streamlit run app.py
```
*Access dashboard at `http://localhost:8501`.*

### Step 5: Inject Threat Scenarios (Terminal 4)
```bash
# Data Exfiltration (ws2 -> ext_srv):
python3 traffic_generator.py 2

# Internal Reconnaissance Port Scan (ws1 -> db_server):
python3 traffic_generator.py 3

# Unauthorized Database Privilege Abuse on port 5432:
python3 traffic_generator.py 4
```

---

## 🐳 4. Docker & Containerized Deployment

A production `Dockerfile` and `docker-compose.yml` are provided in the root directory.

### Build and Run with Docker Compose:
```bash
docker compose up --build -d
```

### Verify Running Container:
```bash
docker ps
```
*Dashboard will be available at `http://localhost:8501` and REST API at `http://localhost:8080`.*

---

## 🌐 5. Streamlit Community Cloud (Free Cloud Hosting)

1. Fork or push this repository to your GitHub account: `yashwanthPathiwada/explainable-sdn-insider-threat`.
2. Visit [share.streamlit.io](https://share.streamlit.io) and log in.
3. Select your repository, branch `main`, and main file path `app.py`.
4. Click **Deploy!**
*Live URL: `https://explainable-sdn-insider-threat-2serxe4t3erjknebczdese.streamlit.app/`*

---

## 🔍 6. Health Check & Validation Commands

To verify your installation before presenting:
```bash
# 1. Test Feature Engineering:
python feature_engineering.py

# 2. Test Model Training & Evaluation:
python train_detector.py

# 3. Test SHAP & LIME Explainability:
python explainability.py

# 4. Verify REST API:
python -c "import requests; print(requests.get('http://127.0.0.1:8080/api/status').json())"
```
