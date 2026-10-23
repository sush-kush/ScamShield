# ScamShield — PowerShell Launcher
# Run with:  .\start_scamshield.ps1
# Or right-click → "Run with PowerShell"

$ErrorActionPreference = "Stop"
$host.UI.RawUI.WindowTitle = "ScamShield"

Write-Host ""
Write-Host " ==========================================" -ForegroundColor Cyan
Write-Host "  ScamShield - Phishing Risk Assessment" -ForegroundColor Cyan
Write-Host " ==========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Check Python ───────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host " [ERROR] Python not found." -ForegroundColor Red
    Write-Host "         Install Python 3.9+ from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "         Make sure to check 'Add Python to PATH' during install." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
$pyVersion = python --version 2>&1
Write-Host " [OK]    $pyVersion found." -ForegroundColor Green

# ── Step 2: Create venv if missing ────────────────────────────
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host " [SETUP] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host " [OK]    Virtual environment created." -ForegroundColor Green
}

# ── Step 3: Activate venv ─────────────────────────────────────
Write-Host " [INFO]  Activating virtual environment..." -ForegroundColor Gray
& "venv\Scripts\Activate.ps1"

# ── Step 4: Install dependencies ──────────────────────────────
Write-Host " [SETUP] Checking dependencies..." -ForegroundColor Yellow
try {
    pip install -r requirements.txt --quiet --only-binary :all: 2>&1 | Out-Null
} catch {
    Write-Host " [WARN]  Retrying without --only-binary..." -ForegroundColor Yellow
    pip install -r requirements.txt --quiet
}
Write-Host " [OK]    Dependencies ready." -ForegroundColor Green

# ── Step 5: Open browser after 2-second delay ─────────────────
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8000"
} | Out-Null

# ── Step 6: Start server ───────────────────────────────────────
Write-Host ""
Write-Host " [INFO]  ScamShield is running at http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host " [INFO]  Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

python -m uvicorn app:app --host 127.0.0.1 --port 8000
