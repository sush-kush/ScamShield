@echo off
title ScamShield
color 0A
cd /d "%~dp0"

echo.
echo  ==========================================
echo   ScamShield - Phishing Risk Assessment
echo  ==========================================
echo.

:: ── Check Python ───────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo          Install Python 3.9+ from https://www.python.org/downloads/
    echo          Tick "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

:: ── Create venv if missing ─────────────────────────────────────
if not exist "venv\Scripts\python.exe" (
    echo  [SETUP] Creating virtual environment, please wait...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Could not create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK]    Virtual environment created.
)

:: ── Install dependencies using venv python directly ────────────
echo  [SETUP] Checking dependencies...
venv\Scripts\python.exe -m pip install -r requirements.txt -q --only-binary :all: 2>nul
if errorlevel 1 (
    venv\Scripts\python.exe -m pip install -r requirements.txt -q
)
echo  [OK]    Dependencies ready.
echo.

:: ── Kill anything already on port 8000 ────────────────────────
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":8000 "') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: ── Open browser after 3 seconds ──────────────────────────────
start /b cmd /c "timeout /t 3 >nul && start http://127.0.0.1:8000"

:: ── Start server via venv uvicorn directly ─────────────────────
echo  ==========================================
echo   Local:   http://127.0.0.1:8000
echo   Network: http://10.236.184.115:8000
echo.
echo   Browser will open automatically.
echo   Press Ctrl+C to stop ScamShield.
echo  ==========================================
echo.

venv\Scripts\uvicorn.exe app:app --host 0.0.0.0 --port 8000

:: ── Stopped ────────────────────────────────────────────────────
echo.
echo  [INFO] ScamShield has stopped.
pause
