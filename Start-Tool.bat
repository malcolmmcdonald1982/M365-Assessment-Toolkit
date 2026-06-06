@echo off
cd /d "C:\M365 Assessment Toolkit"
start "" /B pythonw backend.py
timeout /t 3 /nobreak >nul
start http://localhost:5000
