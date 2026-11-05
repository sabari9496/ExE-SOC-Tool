@echo off
REM EXE SOC launcher for Windows.  Usage: run.bat [--demo]
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3.9+ is required. Install from python.org and tick "Add to PATH". & pause & exit /b 1)
if not exist .venv\Scripts\python.exe python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt
if errorlevel 1 (echo.& echo ERROR: could not install the required packages ^(flask, flask-socketio, psutil, requests^). Check your internet connection and run run.bat again. Do not press Ctrl+C while it installs. & pause & exit /b 1)
if "%SOC_ADMIN_PASSWORD%"=="" echo WARNING: using default passwords. Set SOC_ADMIN_PASSWORD, SOC_ANALYST_PASSWORD, SOC_VIEWER_PASSWORD before real use.
net session >nul 2>&1 || echo WARNING: not running as Administrator - the Windows Security log cannot be read. Close this and use "Run as administrator".
echo Starting EXE SOC on http://127.0.0.1:5000
python app.py %*
pause
