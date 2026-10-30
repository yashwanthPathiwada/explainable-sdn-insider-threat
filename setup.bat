@echo off
REM =============================================================================
REM Automated Setup & Run Script for Windows
REM =============================================================================
echo ========================================================================
echo   Explainable AI-Based Insider Threat Detection in SDN (SHAP/LIME)
echo   Setting up Python Virtual Environment & Dependencies...
echo ========================================================================

python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [+] Launching Project Demonstration Runner...
python run_demo.py
pause
