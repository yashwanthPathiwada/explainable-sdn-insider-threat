#!/usr/bin/env bash
# =============================================================================
# Automated Setup & Run Script for Linux / macOS
# =============================================================================
set -e

echo "========================================================================"
echo "  Explainable AI-Based Insider Threat Detection in SDN (SHAP/LIME)"
echo "  Setting up Python Virtual Environment & Dependencies..."
echo "========================================================================"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[+] Virtual environment created."
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Starting Demonstration Server..."
python run_demo.py
