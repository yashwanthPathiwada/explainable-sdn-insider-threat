#!/usr/bin/env python3
"""
=============================================================================
Turnkey Demonstration & Evaluation Runner
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: run_demo.py
=============================================================================
Description:
    One-click evaluation script for academic presentations, grading reviews,
    and rapid local execution:
      1. Initializes database and trains ML models (if not present).
      2. Starts the Ryu Controller & Mitigation REST API service in the background.
      3. Injects multi-scenario enterprise traffic (Benign + Exfiltration + Port Scan + DB Abuse).
      4. Launches the Streamlit Interactive Dashboard on http://localhost:8501.
"""

import os
import sys
import time
import subprocess
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
DB_PATH = os.path.join(DATA_DIR, 'flow_records.db')
SUPERVISED_MODEL = os.path.join(MODEL_DIR, 'supervised_rf.pkl')


def main():
    print("=" * 75)
    print("  Explainable AI-Based Insider Threat Detection in SDN (SHAP/LIME)")
    print("  Final Year Project Prototype • Turnkey Demonstration Runner")
    print("=" * 75)

    # Step 1: Check / Train Models
    if not os.path.exists(SUPERVISED_MODEL):
        print("\n[Step 1/4] Trained detection models not found. Running training pipeline...")
        from train_detector import ThreatDetectionEngine
        engine = ThreatDetectionEngine()
        engine.train()
    else:
        print("\n[Step 1/4] Detection models (RF + Isolation Forest + Scaler) verified.")

    # Step 2: Ensure database has traffic telemetry
    print("\n[Step 2/4] Verifying network flow telemetry database...")
    from traffic_generator import (
        stream_benign_traffic, inject_data_exfiltration,
        inject_port_scan, inject_privilege_abuse
    )
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM flow_records")
    flow_count = cursor.fetchone()[0]
    conn.close()

    if flow_count < 100:
        print(f"  Only {flow_count} flows found. Injecting baseline & attack scenarios...")
        stream_benign_traffic(duration_sec=5, sleep_interval=0.2)
        inject_data_exfiltration(attacker_ip='10.0.1.11', bursts=12)
        inject_port_scan(attacker_ip='10.0.1.10', num_ports=25)
        inject_privilege_abuse(attacker_ip='10.0.1.10', queries=10)
    else:
        print(f"  Telemetry database contains {flow_count:,} records.")

    # Step 3: Start Ryu Controller / Mitigation REST Service
    print("\n[Step 3/4] Starting Controller Mitigation REST API on http://127.0.0.1:8080...")
    from ryu_controller import start_rest_api_server
    start_rest_api_server(port=8080)
    time.sleep(1)

    # Step 4: Launch Streamlit Dashboard
    print("\n[Step 4/4] Launching Interactive SOC Analyst Dashboard...")
    print("  Access the Dashboard at: http://localhost:8501")
    print("  Press Ctrl+C to terminate the demonstration server.")
    print("-" * 75)

    cmd = [sys.executable, "-m", "streamlit", "run", os.path.join(BASE_DIR, "app.py"), "--server.port=8501", "--server.headless=true"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nDemonstration session ended.")


if __name__ == '__main__':
    main()
