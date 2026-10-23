# ScamShield — Project Report

**Course / Programme:** Cybersecurity Fundamentals / Beginner–Intermediate Project
**Submission Type:** Individual Project
**Application Domain:** Defensive Cybersecurity / Social Engineering Awareness

---

## 1. Title

**ScamShield: A Rule-Based Phishing and Scam Message Risk Assessment Tool**

---

## 2. Abstract

Phishing and social engineering attacks remain among the most prevalent
cybersecurity threats facing ordinary users. ScamShield is a locally hosted
web application that analyses suspicious text messages and URLs for indicators
commonly associated with phishing and fraud. The tool employs a transparent,
rule-based detection engine to assign a risk score (0–100) and risk level
(LOW / MEDIUM / HIGH) to submitted input. All analysis is performed locally
with no external API dependencies, no data storage, and no URL crawling.
The project is intended as an educational demonstration of defensive
cybersecurity principles, explainable risk assessment, and secure
web application development.

---

## 3. Introduction

Social engineering attacks manipulate human psychology rather than exploiting
technical vulnerabilities. Phishing messages impersonate trusted organisations,
create a sense of urgency, and request sensitive information or payment from
their victims.

This project builds a tool that makes the detection logic visible to the user
— showing exactly which patterns were detected and why they raise concern.
This transparency is intentional: understanding *why* something is suspicious
helps users develop their own critical thinking skills, not just rely on an
opaque tool.

The application is built with Python, FastAPI, and vanilla JavaScript. It
runs entirely on a local Windows machine with no cloud services, paid APIs,
or database required.

---

## 4. Problem Statement

Everyday users frequently receive suspicious messages via SMS, email, or
chat applications. Without a technical background, it is difficult to quickly
assess whether a message represents a genuine threat. Existing solutions
(commercial email filters, browser safe-browsing features) are often opaque,
cloud-dependent, or unavailable for raw message analysis. A beginner student
also needs a project that can be explained, modified, and understood from
first principles.

**Gap:** There is a lack of simple, locally runnable, explainable tools that
help ordinary users understand *why* a message looks suspicious.

---

## 5. Motivation

- Growing prevalence of SMS and WhatsApp phishing (smishing) in India and worldwide
- Need for cybersecurity education tools that are accessible and transparent
- Desire to apply foundational programming skills to a real-world security problem
- Project scope appropriate for 1–2 weeks of individual development

---

## 6. Objectives

1. Implement a working, explainable, rule-based scam detection engine in Python
2. Build a FastAPI web service that serves both the UI and the analysis API
3. Design a clean, professional cybersecurity-themed interface
4. Follow secure coding practices throughout the implementation
5. Document the detection logic, scoring system, and architecture clearly
6. Demonstrate the tool against a range of synthetic test cases

---

## 7. Existing Problem / Current Situation

### Current landscape

| Solution | Limitation |
|----------|-----------|
| Commercial anti-spam filters | Opaque — user cannot see why a message was flagged |
| Google Safe Browsing | URL-only, cloud-dependent, not available for raw message text |
| Manual checking | Requires cybersecurity knowledge most users do not have |
| Paid threat intelligence APIs | Not accessible to students or low-resource users |

### What is missing

A simple, free, locally runnable tool that:
- accepts raw message text
- explains its reasoning step by step
- requires no accounts, keys, or internet connection
- can be studied and modified by a student

---

## 8. Proposed Solution

ScamShield is a single-file Python application that:

1. Accepts a message and optional URL via a web form
2. Analyses the message against six categories of scam indicators using
   word-boundary keyword matching
3. Separately analyses the URL for structural red flags without visiting it
4. Combines scores with a documented, capped scoring formula
5. Returns a risk score, risk level, list of indicators, plain-language
   explanation, and recommended actions
6. Renders results in a professional dark-themed web interface

All components are contained in four files. The entire application can be
understood, modified, and extended by a beginner Python developer.

---

## 9. System Requirements

### Hardware

- Any modern Windows 10 / Windows 11 laptop or desktop
- Minimum 4 GB RAM (typical for Python web development)
- ~100 MB disk space (mostly for the Python virtual environment)

### Software

| Requirement | Version |
|-------------|---------|
| Windows | 10 or 11 |
| Python | 3.9 or later |
| pip | Bundled with Python 3.9+ |
| Web browser | Any modern browser (Chrome, Edge, Firefox) |

### Network

- No internet connection required after installation
- Runs on `localhost` (127.0.0.1:8000)

---

## 10. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Python 3.9+ | Readable, beginner-friendly, strong ecosystem |
| Web framework | FastAPI 0.111.0 | Modern, fast, built-in validation, auto-docs |
| ASGI server | Uvicorn 0.29.0 | Lightweight, simple to run |
| Data validation | Pydantic 2.7.1 | Automatic request validation, clear error messages |
| Frontend | HTML5 / CSS3 | No build step, easy to read and edit |
| Interactivity | Vanilla JavaScript (Fetch API) | No framework dependencies |
| Pattern matching | Python `re` module | Standard library, no extra install |

**Deliberately excluded:**
- React / Vite (unnecessary complexity for this scope)
- Database (no persistent storage needed)
- External AI / ML APIs (out of scope for this phase)
- Kali Linux tools (this is a defensive, not offensive, project)

---

## 11. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      User's Browser                      │
│  ┌────────────────────────────────────────────────────┐  │
│  │  HTML/CSS/JS Page                                  │  │
│  │  - Message input textarea                         │  │
│  │  - URL input field                                │  │
│  │  - Fetch API → POST /api/analyze                  │  │
│  │  - Renders JSON response (score, indicators, recs)│  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTP (localhost only)
┌──────────────────────────▼──────────────────────────────┐
│               FastAPI Application (app.py)               │
│                                                          │
│  GET /  ──────────────────────────► HTML page           │
│                                                          │
│  POST /api/analyze                                       │
│    │                                                     │
│    ├── AnalyzeRequest (Pydantic validation)              │
│    ├── analyze_message() ──► text rule engine           │
│    ├── analyze_url()     ──► URL structure checks       │
│    ├── calculate_risk_score()                            │
│    ├── determine_risk_level()                            │
│    ├── build_explanation()                               │
│    ├── generate_recommendations()                        │
│    └── AnalyzeResponse (JSON)                            │
│                                                          │
│  Security middleware: adds HTTP security headers         │
└──────────────────────────────────────────────────────────┘
             (No outbound network requests made)
             (No data written to disk or database)
```

---

## 12. Data Flow

```
User types message + URL
         │
         ▼
Browser validates (not empty, within length limit)
         │
         ▼
POST /api/analyze  ──── JSON body ────►  FastAPI
                                              │
                                    Pydantic validates
                                    (length, type)
                                              │
                                    analyze_message()
                                    ├── check urgency keywords
                                    ├── check sensitive-info keywords
                                    ├── check financial keywords
                                    ├── check threatening keywords
                                    ├── check impersonation keywords
                                    └── check prize/reward keywords
                                              │
                                    analyze_url()
                                    ├── check scheme (HTTP vs HTTPS)
                                    ├── check for IP address domain
                                    ├── check for URL shortener
                                    ├── check subdomain count
                                    ├── check suspicious keywords in URL
                                    ├── check URL length
                                    └── check special characters (@, %, //)
                                              │
                                    calculate_risk_score()
                                    (message_score + url_score × 0.8, clamped 0–100)
                                              │
                                    determine_risk_level()
                                    (LOW / MEDIUM / HIGH)
                                              │
                                    build_explanation()
                                    generate_recommendations()
                                              │
                                    JSON response ──────────► Browser
                                                                  │
                                                         Renders results in UI
                                                         (HTML-escaped for safety)
```

---

## 13. Detection Methodology

The detection engine applies seven rule groups. Each group defines:

- **keywords**: a list of indicator phrases
- **score**: points added per matched keyword
- **max_score**: ceiling for this category's total contribution
- **label / detail**: human-readable description shown to the user

Matching uses Python `re.search()` with `\b` word-boundary anchors to prevent
partial-word false positives (e.g. the word "pin" must not match inside "pinned").
Input is converted to lower-case before matching.

### Rule Group Summary

| Group | Keywords (sample) | Per-match | Cap |
|-------|-------------------|-----------|-----|
| Urgency / Pressure | urgent, act now, last warning, within 24 hours | 8 pts | 24 pts |
| Sensitive Info Request | OTP, PIN, password, CVV, card number, Aadhaar | 20 pts | 40 pts |
| Financial Language | UPI, bank account, transfer, refund, lottery | 6 pts | 18 pts |
| Threatening Language | account suspended, legal action, arrest, warrant | 15 pts | 30 pts |
| Impersonation | SBI, government, income tax, Amazon, customer support | 7 pts | 21 pts |
| Prize / Reward | congratulations, lucky winner, cash prize | 10 pts | 20 pts |
| URL Analysis | HTTP, IP domain, shortener, suspicious keywords | varies | 30 pts |

### URL Analysis Detail

The URL is analysed statically (no HTTP request is made):

| Check | Finding | Score added |
|-------|---------|-------------|
| HTTP scheme | Plain HTTP (not HTTPS) | +10 |
| Missing scheme | No https:// prefix | +8 |
| IP address domain | e.g. `192.168.1.1` | +20 |
| URL shortener | `bit.ly`, `tinyurl.com`, etc. | +15 |
| Excessive subdomains | 3+ dots in domain | +10 |
| Suspicious keywords in URL | login, verify, secure, password, etc. | +4 per keyword, max +16 |
| Unusually long URL | > 200 characters | +8 |
| @ symbol in URL | Classic misdirection technique | +12 |
| Encoded characters (%, //) | Obfuscation technique | +8 / +5 |

URL score is capped at 30 before weighting.

---

## 14. Risk Scoring Method

### Formula

```
message_score = sum of all triggered category scores (each capped at category max)
url_score     = sum of URL analysis findings (capped at 30)
combined      = message_score + floor(url_score × 0.8)
final_score   = max(0, min(100, combined))
```

### Rationale for URL weighting (0.8)

URL analysis alone (e.g. a plain HTTP URL with no suspicious message) could
produce false positives. Weighting the URL contribution slightly lower (80%)
prevents a clean message with a borderline URL from triggering unnecessarily
high scores.

### Thresholds

| Score | Level | Interpretation |
|-------|-------|----------------|
| 0–29 | LOW | Few or no common scam patterns detected |
| 30–59 | MEDIUM | Some suspicious patterns; independent verification recommended |
| 60–100 | HIGH | Multiple strong scam indicators; treat with extreme caution |

### Worked example

**Input:** "Urgent: Your SBI account has been suspended. Enter your OTP to verify."

| Category | Matched | Score |
|----------|---------|-------|
| Urgency | urgent | 8 |
| Sensitive Info | OTP | 20 |
| Threatening | account suspended | 15 |
| Impersonation | SBI | 7 |
| **Total message** | | **50** |

**Input URL:** `http://sbi-secure-login.xyz`

| URL Check | Finding | Score |
|-----------|---------|-------|
| HTTP scheme | yes | 10 |
| Suspicious keywords | login, secure | 8 |
| **Total URL** | | **18** |

```
combined = 50 + floor(18 × 0.8) = 50 + 14 = 64
final_score = min(100, 64) = 64  →  HIGH
```

---

## 15. Implementation

### Key functions in app.py

| Function | Responsibility |
|----------|---------------|
| `check_category(text, rule)` | Checks a single rule category against lower-cased text; returns matched keywords and capped score |
| `analyze_message(message)` | Runs all six text rule groups; returns total score and list of triggered indicators |
| `analyze_url(url)` | Runs all URL structural checks; returns score and list of URL findings |
| `calculate_risk_score(msg, url)` | Applies weighting and clamps result to 0–100 |
| `determine_risk_level(score)` | Maps score integer to "LOW", "MEDIUM", or "HIGH" |
| `build_explanation(...)` | Produces a plain-language narrative from the indicator data |
| `generate_recommendations(...)` | Returns category-aware safety advice list |

### Security coding practices applied

- **Input validation:** Pydantic model enforces type and maximum length
- **Input sanitisation:** Input is lower-cased before regex matching; original text is not executed
- **Output escaping:** All user-supplied text rendered via JavaScript uses a `textContent` assignment or an `escHtml()` helper function, preventing XSS
- **No command execution:** No `eval()`, `exec()`, `subprocess`, or `os.system()` calls
- **No database:** No SQL injection surface
- **No outbound requests:** The URL is analysed as a string only; no HTTP requests are made to it
- **Security headers:** Middleware adds `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Cache-Control: no-store`
- **No logging of sensitive content:** Input messages are not written to disk or logs

---

## 16. API Design

### Endpoint: POST /api/analyze

**Request model (Pydantic):**

```python
class AnalyzeRequest(BaseModel):
    message: str   # required, max 10 000 characters
    url: Optional[str] = None  # optional, max 2 000 characters
```

**Response model (Pydantic):**

```python
class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    detected_indicators: list
    explanation: str
    recommendations: list
```

**Error handling:**
- Missing `message` → HTTP 422 Unprocessable Entity
- Message > 10 000 chars → HTTP 422 with descriptive error
- URL > 2 000 chars → HTTP 422 with descriptive error
- Unexpected server error → HTTP 500

### FastAPI automatic documentation

When the server is running, interactive API documentation is available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

---

## 17. User Interface

### Design choices

| Choice | Rationale |
|--------|-----------|
| Dark theme (#0d1117 base) | Professional, cybersecurity/SOC-inspired; reduces eye strain |
| Sticky header | Navigation anchor always visible |
| Score dial | Immediate visual risk indicator |
| Colour-coded badges | LOW=green, MEDIUM=amber, HIGH=red — universal risk language |
| Keyword chips | Shows exactly which words triggered each category |
| Privacy notice at top | Transparency builds user trust |
| Example buttons | Allows immediate demonstration without typing |
| Responsive layout | Works on phone and desktop |

### Security in the UI

- User input is never inserted as raw HTML; `textContent` and `escHtml()` are used
- The `maxlength` attribute on inputs provides a client-side complement to server-side validation
- No `eval()` calls in JavaScript
- No external JavaScript libraries loaded (no CDN dependency)

---

## 18. Testing Strategy

### Types of testing performed

1. **Manual functional testing** via the web interface
2. **API testing** via PowerShell `Invoke-RestMethod` or browser
3. **Edge case testing** with empty, very long, and malformed inputs
4. **Example-driven testing** using the 8 built-in synthetic test cases

### Test approach

For each test case, the tester:
1. Loads the example or types the input
2. Clicks "Analyze Message"
3. Records the risk score, risk level, and detected indicators
4. Compares against expected results

---

## 19. Test Cases

> **Note:** Results below are example expected values based on the detection logic.
> Actual results should be verified by running the application.

### Test Case 1 — Clear Phishing (Banking Scam)

**Input message:**
> "URGENT: Your SBI bank account has been suspended due to suspicious activity.
> Verify your account immediately by clicking this link or your account will
> be permanently blocked. Enter your card number, PIN, and OTP to confirm."

**Input URL:** `http://sbi-verify-account.xyz/login`

| Expected result | Value |
|----------------|-------|
| Risk level | HIGH |
| Risk score | 60–100 |
| Triggered categories | Urgency, Sensitive Info, Threatening, Impersonation |
| URL flags | HTTP, suspicious keywords |

---

### Test Case 2 — Prize Scam

**Input message:**
> "Congratulations! You are the lucky winner of Rs 10 Lakh cash prize lottery!
> Claim your reward now by providing your bank account number and CVV."

| Expected result | Value |
|----------------|-------|
| Risk level | HIGH |
| Triggered categories | Prize/Reward, Sensitive Info, Financial |

---

### Test Case 3 — Legitimate Message

**Input message:**
> "Hi, this is a reminder that your appointment with Dr. Sharma is scheduled
> for tomorrow at 10:30 AM. Please call 011-2345-6789 to reschedule."

| Expected result | Value |
|----------------|-------|
| Risk level | LOW |
| Risk score | 0–15 |
| Triggered categories | None expected |

---

### Test Case 4 — Empty Input

**Input:** (empty)

| Expected result | Value |
|----------------|-------|
| Behaviour | Client-side error: "Please enter a message to analyse." |
| Server call made | No |

---

### Test Case 5 — Suspicious URL Only

**Input message:** "Please log in to your account."

**Input URL:** `http://192.168.1.1/paypal-login/verify?user=test`

| Expected result | Value |
|----------------|-------|
| Risk level | MEDIUM–HIGH |
| URL flags | HTTP, IP address domain, suspicious keywords (login, verify) |

---

### Test Case 6 — URL Shortener

**Input URL:** `https://bit.ly/claim-prize-now`

| Expected result | Value |
|----------------|-------|
| URL flags | URL shortener detected, suspicious keyword (claim, prize) |

---

### Test Case 7 — Malformed URL

**Input URL:** `not a url at all`

| Expected result | Value |
|----------------|-------|
| Behaviour | Graceful handling; no crash; no indicators from URL |

---

### Test Case 8 — Input Exceeding Limit

**Input:** 10 001 characters

| Expected result | Value |
|----------------|-------|
| Behaviour | HTTP 422 Validation Error from server |

---

## 20. Results

> **Status:** Results in this section are example expected values.
> Run the application and update this table with actual observed results
> after performing the tests described in Section 19.

| Test Case | Expected Level | Observed Level | Pass/Fail |
|-----------|---------------|----------------|-----------|
| Banking Scam | HIGH | *(run to verify)* | — |
| Prize Scam | HIGH | *(run to verify)* | — |
| Tax Scam | HIGH | *(run to verify)* | — |
| Delivery Scam | MEDIUM–HIGH | *(run to verify)* | — |
| Legitimate (doctor) | LOW | *(run to verify)* | — |
| Suspicious URL | MEDIUM–HIGH | *(run to verify)* | — |
| Empty input | Error (no call) | *(run to verify)* | — |
| 10001-char input | 422 error | *(run to verify)* | — |

---

## 21. Security Considerations

### Threats addressed

| Threat | Mitigation |
|--------|-----------|
| XSS via malicious message content | Output escaped with `textContent` / `escHtml()` |
| Oversized input (DoS) | Server-side length validation via Pydantic |
| Clickjacking | `X-Frame-Options: DENY` header |
| MIME sniffing | `X-Content-Type-Options: nosniff` header |
| Reflected XSS | `X-XSS-Protection: 1; mode=block` header |
| Information leakage via cache | `Cache-Control: no-store` header |
| Sensitive data in server logs | Input messages are not logged |
| Command injection | No shell commands, `eval()`, or `exec()` used |
| SQL injection | No database used |
| SSRF (requesting submitted URLs) | No HTTP requests made to submitted URLs |

### Out-of-scope threats (acceptable for educational project)

- HTTPS for local-only deployment (add a reverse proxy like Nginx for production)
- Rate limiting (acceptable for a local tool; add for any public deployment)
- Authentication (not required for a local analysis tool)

---

## 22. Privacy Considerations

| Principle | Implementation |
|-----------|---------------|
| Data minimisation | Only message and URL are collected; no user identity data |
| No storage | No database, no file writes of user input |
| No third-party sharing | No external API calls with user data |
| Local processing | Runs on localhost; data never leaves the machine |
| Transparency | Privacy notice displayed prominently in the UI |
| User warning | Discourages entering real credentials or sensitive personal data |

---

## 23. Limitations

1. **Rule-based only:** Cannot detect novel phishing language not in keyword lists
2. **No semantic understanding:** A cybersecurity article discussing scams may score HIGH
3. **English language only:** Multilingual phishing is not detected
4. **No URL visiting:** Cannot detect malicious page content, redirects, or malware
5. **No threat intelligence:** Does not check URLs against known phishing databases
6. **Threshold subjectivity:** The 30/60 thresholds are reasonable estimates, not validated cutoffs
7. **False positives:** Legitimate bank communications may score MEDIUM
8. **False negatives:** Sophisticated scams avoiding keyword patterns will score LOW

---

## 24. Future Enhancements

### Phase 2 (next 1–2 months)

| Enhancement | Description |
|------------|-------------|
| Language support | Add Hindi, Tamil keyword lists |
| Regex patterns | Detect UPI ID formats, suspicious phone numbers |
| Domain age check | Young domains (< 30 days) are a red flag |
| VirusTotal integration | Free tier URL reputation check (optional, requires API key) |

### Phase 3 (longer term)

| Enhancement | Description |
|------------|-------------|
| ML classifier | Train Naive Bayes on public phishing datasets (e.g. PhishTank) |
| Browser extension | Analyse messages in Gmail, WhatsApp Web in-place |
| Bulk analysis | Upload a CSV of messages for batch assessment |
| Reporting | Optional local logging of flagged messages for research |

---

## 25. Conclusion

ScamShield demonstrates that a useful, explainable cybersecurity tool can be
built with minimal dependencies and a small codebase. The rule-based approach,
while not as powerful as machine learning, has the significant advantage of
being fully transparent — every indicator, every score contribution, and every
recommendation can be traced directly to a line of code.

The project fulfils its core objectives: a working detection engine, a clean
user interface, secure coding practices, and complete documentation. It
provides a solid foundation for future enhancements such as machine learning
integration, multilingual support, and threat intelligence feeds.

Most importantly, it demonstrates that cybersecurity tools do not need to be
opaque, cloud-dependent, or expensive to be valuable for everyday users.

---

## 26. References

1. NCSC (UK). *Phishing attacks: defending your organisation.*
   https://www.ncsc.gov.uk/guidance/phishing

2. CISA (USA). *Phishing — Recognise and Report.*
   https://www.cisa.gov/resources-tools/resources/phishing-guidance

3. Indian Computer Emergency Response Team (CERT-In). *Cyber Swachhta Kendra.*
   https://www.csk.gov.in/

4. PhishTank. *Community Anti-Phishing Site.*
   https://www.phishtank.com/

5. OWASP. *Input Validation Cheat Sheet.*
   https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

6. OWASP. *Cross Site Scripting Prevention Cheat Sheet.*
   https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

7. FastAPI Documentation. https://fastapi.tiangolo.com/

8. Pydantic Documentation. https://docs.pydantic.dev/

9. Mitnick, K. D., & Simon, W. L. (2002). *The Art of Deception.*
   Wiley Publishing. *(Reference for social engineering techniques)*

10. Cybercrime Portal, India. https://cybercrime.gov.in/

---

*End of Project Report — ScamShield v1.0*
