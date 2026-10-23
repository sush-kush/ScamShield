# ScamShield
### Defensive Phishing & Scam Message Risk Assessment Tool

> **IBM SkillsBuild Cyber Security 2026 — BharatCares Submission**
> Author: Sushmitha M

---

## Project Description

ScamShield is a locally hosted web application that analyses suspicious text messages and URLs for indicators commonly associated with phishing, social engineering, and online fraud.

The user pastes a suspicious message (SMS, email excerpt, or chat message), optionally provides a URL, and receives:

- A **risk score** from 0 to 100
- A **risk level**: LOW, MEDIUM, or HIGH
- A list of **detected warning indicators** with matched keywords
- A plain-language **explanation** of the assessment
- **Recommended safe actions**

> **Important:** ScamShield produces a *risk assessment*, not a definitive fraud verdict. It is an educational tool — not a certified fraud detection service.

---

## Problem Statement

Everyday users regularly receive suspicious messages via SMS, WhatsApp, and email. Without cybersecurity knowledge, it is difficult to assess whether a message is a scam. Existing commercial tools are opaque (they don't explain *why* something was flagged) or require cloud connectivity and paid APIs.

ScamShield fills this gap: a free, local, fully explainable tool that shows exactly which patterns triggered the alert and why they are suspicious.

---

## Features

| Feature | Description |
|---------|-------------|
| Message analysis | 6 indicator categories: urgency, sensitive info, financial language, threats, impersonation, prize/reward |
| URL analysis | 9 structural checks: HTTP, IP domain, shorteners, subdomains, suspicious keywords, length, special characters |
| Risk scoring | Transparent capped scoring formula, 0–100 |
| Risk level badge | LOW / MEDIUM / HIGH with colour coding |
| Detected indicators | Each category shown with matched keywords |
| Plain-language explanation | Human-readable summary of the assessment |
| Recommended actions | Category-aware safety advice |
| 8 built-in examples | Pre-loaded synthetic test cases for demonstration |
| Privacy notice | Confirms no data is stored or transmitted |
| Security headers | X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, etc. |
| Input validation | Server-side length limits (10 000 / 2 000 chars) via Pydantic |
| Output escaping | All user text HTML-escaped before rendering (XSS prevention) |
| Responsive UI | Works on desktop and mobile |

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.9+ (tested on 3.14.5) |
| Web Framework | FastAPI | 0.115.12 |
| ASGI Server | Uvicorn | 0.34.3 |
| Data Validation | Pydantic | 2.14.1 |
| Frontend | HTML5 / CSS3 / Vanilla JS | — |
| Pattern Matching | Python `re` (stdlib) | — |

---

## Dataset Statement

**Dataset: Not applicable to the current rule-based prototype.**

ScamShield v1.0 uses a hand-crafted keyword rule engine — not a machine learning model. No training dataset is required or used. Synthetic test cases are used for functional testing only.

Future versions may incorporate the PhishTank public phishing dataset or UCI SMS Spam Collection for ML classifier training. See Future Enhancements.

---

## Architecture

```
Browser (HTML/CSS/JS)
        |
        |  GET /          -> Returns HTML page
        |  POST /api/analyze -> JSON in, JSON out
        v
FastAPI Application (Sushmitha_ScamShield.py)
        |
        |-- analyze_message()   -> 6 keyword rule categories
        |-- analyze_url()       -> 9 URL structural checks
        |-- calculate_risk_score() -> weighted, clamped 0-100
        |-- determine_risk_level() -> LOW / MEDIUM / HIGH
        |-- build_explanation()
        |-- generate_recommendations()
        |
        (No database. No outbound requests. No data stored.)
```

---

## Detection Methodology

### Message Analysis — 6 Categories

| Category | Sample Keywords | Per Match | Max Cap |
|----------|----------------|-----------|---------|
| Urgency / Pressure | urgent, act now, last warning, within 24 hours | 8 pts | 24 pts |
| Sensitive Info Request | OTP, PIN, password, CVV, card number, Aadhaar | 20 pts | 40 pts |
| Financial Language | UPI, bank account, transfer, refund, lottery | 6 pts | 18 pts |
| Threatening Language | account suspended, legal action, arrest, penalty | 15 pts | 30 pts |
| Impersonation | SBI, government, income tax, Amazon, customer support | 7 pts | 21 pts |
| Prize / Reward | congratulations, lucky winner, cash prize, gift card | 10 pts | 20 pts |

Matching uses Python `re` word-boundary anchors (`\b`) to prevent partial-word false positives (e.g. `"pin"` will not match `"pinned"`).

### URL Analysis — 9 Checks

| Check | Score Added |
|-------|-------------|
| HTTP instead of HTTPS | +10 |
| Missing scheme | +8 |
| IP address as domain | +20 |
| URL shortener (bit.ly etc.) | +15 |
| Excessive subdomains (3+ dots) | +10 |
| Suspicious keywords in URL | +4 each, max +16 |
| URL longer than 200 characters | +8 |
| @ symbol in URL | +12 |
| Encoded characters (%2F, %40) | +8 |

URL score is capped at 30 before weighting.

---

## Risk Scoring

```
message_score = sum of triggered category scores (each capped per category)
url_score     = sum of URL check scores (capped at 30)
combined      = message_score + floor(url_score x 0.8)
final_score   = max(0, min(100, combined))
```

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0 - 29 | LOW | Few or no scam patterns detected |
| 30 - 59 | MEDIUM | Some suspicious patterns — verify before acting |
| 60 - 100 | HIGH | Multiple strong indicators — treat with extreme caution |

---

## Project Structure

```
ScamShield/
|-- Sushmitha_ScamShield.py   <- Submission code file (FastAPI app + frontend)
|-- app.py                    <- Working copy (identical to submission file)
|-- requirements.txt          <- Python dependencies
|-- README.md                 <- This file
|-- PROJECT_REPORT.md         <- Markdown report
|-- run.bat                   <- One-click Windows launcher
|-- start_scamshield.ps1      <- PowerShell launcher
|-- test_scamshield.py        <- Test suite (37/37 passing)
|-- Procfile                  <- For cloud deployment (Render.com)
|-- .gitignore
|-- venv/                     <- Virtual environment (not committed to git)
```

---

## Installation — Windows

### Prerequisites
- Python 3.9 or later — download from https://www.python.org/downloads/
- During install, tick **"Add Python to PATH"**

### Step 1 — Open terminal in the ScamShield folder

```powershell
cd "C:\path\to\ScamShield"
```

### Step 2 — Create virtual environment

```powershell
python -m venv venv
```

### Step 3 — Activate virtual environment

**Command Prompt:**
```cmd
venv\Scripts\activate.bat
```

**PowerShell:**
```powershell
venv\Scripts\Activate.ps1
```

> If PowerShell blocks the script, run once:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Step 4 — Install dependencies

```powershell
pip install -r requirements.txt
```

---

## Running the Application

```powershell
venv\Scripts\uvicorn.exe Sushmitha_ScamShield:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser at:

```
http://127.0.0.1:8000
```

To stop the server, press **Ctrl+C**.

> **Tip:** You can also just double-click `run.bat` to launch automatically.

---

## Example Usage

1. Open `http://127.0.0.1:8000` in your browser
2. Paste a suspicious message into the text box
3. Optionally paste a suspicious URL
4. Click **Analyze Message**
5. Review the risk score, indicators, explanation, and recommendations

**Example scam message to try:**
```
URGENT: Your SBI bank account has been suspended. Verify your account
immediately or it will be permanently blocked. Enter your PIN and OTP
at: http://sbi-verify-account.xyz/login
```

Expected result: **HIGH risk, score ~92/100**

---

## API Endpoint

### POST /api/analyze

**Request:**
```json
{
  "message": "Your suspicious message here",
  "url": "http://suspicious-link.xyz/login"
}
```

**Response:**
```json
{
  "risk_score": 92,
  "risk_level": "HIGH",
  "detected_indicators": [...],
  "explanation": "This message received a HIGH risk score...",
  "recommendations": [...]
}
```

Interactive API docs available at `http://127.0.0.1:8000/docs` when server is running.

---

## Testing

Run the self-contained test suite (no live server needed):

```powershell
venv\Scripts\python.exe test_scamshield.py
```

**Result: 37/37 tests passed** on Python 3.14.5, FastAPI 0.115.12, Pydantic 2.14.1.

Tests cover: legitimate messages, banking scams, prize scams, empty input, whitespace, suspicious URLs, IP-address domains, URL shorteners, malformed URLs, score clamping, threshold boundaries, word-boundary matching, and recommendations.

---

## Limitations

1. **Rule-based only** — cannot detect novel phishing language not in keyword lists
2. **No semantic understanding** — a cybersecurity article about scams may score HIGH
3. **English only** — multilingual phishing (Hindi, Tamil) not detected
4. **No URL visiting** — cannot detect malicious page content or redirects
5. **No threat intelligence** — does not check URLs against phishing blacklists
6. **False positives possible** — legitimate bank messages may score MEDIUM
7. **False negatives possible** — sophisticated scams avoiding keywords will score LOW

---

## Future Enhancements

| Enhancement | Description |
|------------|-------------|
| Multilingual support | Hindi, Tamil keyword lists |
| ML classifier | Naive Bayes trained on PhishTank / UCI SMS Spam dataset |
| VirusTotal API | Optional URL reputation check |
| Domain age check | Newly registered domains are a phishing red flag |
| Browser extension | Analyse messages in Gmail/WhatsApp Web |
| Bulk analysis | CSV upload for batch assessment |

---

## Ethical Use

ScamShield is built for **defensive** cybersecurity education only.

**Permitted:** Analysing messages you have personally received, educational demonstrations, learning about social engineering for defensive awareness.

**Not permitted:** Using detection logic to craft scams that evade detection, testing other people's messages without consent, presenting results as a legally admissible fraud verdict.

**Report real scams:**
- India: https://cybercrime.gov.in
- UK: https://www.ncsc.gov.uk
- USA: https://reportfraud.ftc.gov

---

*ScamShield v1.0 — IBM SkillsBuild Cyber Security 2026 — BharatCares Submission*
