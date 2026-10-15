@echo off
title PhishShield AI - Web Dashboard Launcher
echo ============================================================
echo   Starting PhishShield AI Interactive Web Dashboard...
echo ============================================================
cd /d "%~dp0"
python -m streamlit run app.py
pause
