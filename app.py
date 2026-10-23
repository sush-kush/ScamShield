"""
ScamShield - Defensive Cybersecurity Risk Assessment Tool
==========================================================
A beginner-friendly, rule-based phishing and scam message analyser.

This application analyses user-submitted text messages and optional URLs
for patterns commonly associated with phishing, scams, and social engineering.

It produces a RISK ASSESSMENT — not a definitive fraud verdict.
All analysis is performed locally; no submitted data is stored or transmitted.

Author  : ScamShield Project
Purpose : Cybersecurity education
"""

import re
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Input model for the /api/analyze endpoint."""
    message: str
    url: Optional[str] = None

    # Limit input size to prevent abuse (10 000 characters each)
    @field_validator("message")
    @classmethod
    def message_must_not_be_too_long(cls, v: str) -> str:
        if len(v) > 10_000:
            raise ValueError("Message exceeds maximum allowed length of 10 000 characters.")
        return v

    @field_validator("url")
    @classmethod
    def url_must_not_be_too_long(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 2_000:
            raise ValueError("URL exceeds maximum allowed length of 2 000 characters.")
        return v


class AnalyzeResponse(BaseModel):
    """Output model returned by the /api/analyze endpoint."""
    risk_score: int
    risk_level: str
    detected_indicators: list
    explanation: str
    recommendations: list


# ---------------------------------------------------------------------------
# Detection Rule Definitions
# ---------------------------------------------------------------------------
# Each rule has:
#   "keywords"  : list of phrases to search for (case-insensitive)
#   "score"     : points added PER keyword match (capped per category)
#   "max_score" : maximum points this category can contribute
#   "label"     : short display name
#   "detail"    : explanation shown to the user

URGENCY_RULES = {
    "label": "Urgency / Pressure Tactics",
    "detail": "The message uses urgency-creating language to pressure you into acting quickly without thinking.",
    "score": 8,
    "max_score": 24,
    "keywords": [
        "act immediately", "act now", "urgent", "urgently", "immediately",
        "verify now", "click now", "respond now", "last warning",
        "final notice",
        "limited time", "expires today", "expires soon", "time is running out",
        "do not delay", "failure to respond", "within 24 hours", "within 48 hours",
        "as soon as possible", "asap"
    ],
}

SENSITIVE_INFO_RULES = {
    "label": "Sensitive Information Request",
    "detail": "The message asks for private or financial credentials that legitimate organisations never request over messages.",
    "score": 20,
    "max_score": 40,
    "keywords": [
        "otp", "one-time password", "one time password",
        "pin", "password", "cvv", "cvc",
        "bank details", "card number", "card details",
        "account number", "account details",
        "social security", "aadhaar", "pan number",
        "date of birth", "mother's maiden name",
        "security question", "secret answer",
    ],
}

FINANCIAL_RULES = {
    "label": "Financial / Payment Language",
    "detail": "The message contains language related to money transfers, payments, or rewards.",
    "score": 6,
    "max_score": 18,
    "keywords": [
        "payment", "pay now", "transfer money", "wire transfer",
        "refund", "cashback", "money back",
        "prize", "lottery", "jackpot", "won", "winner",
        "free reward", "claim your reward",
        "upi", "bank account", "net banking",
        "credit card", "debit card",
        "bitcoin", "crypto", "cryptocurrency",
        "investment", "double your money",
    ],
}

THREATENING_RULES = {
    "label": "Threatening / Fear-Inducing Language",
    "detail": "The message uses fear-based threats to make you comply without questioning.",
    "score": 15,
    "max_score": 30,
    "keywords": [
        "account suspended", "account blocked", "account closed",
        "account deactivated", "account has been suspended",
        "account will be blocked", "account will be suspended",
        "service suspended", "suspended",
        "legal action", "legal notice", "lawsuit",
        "arrest", "arrested", "warrant",
        "penalty", "fine", "court",
        "police", "cybercrime",
        "blacklisted", "reported to authorities",
    ],
}

IMPERSONATION_RULES = {
    "label": "Impersonation Indicators",
    "detail": "The message claims to be from a trusted institution, which is a common social engineering technique.",
    "score": 7,
    "max_score": 21,
    "keywords": [
        "bank of", "your bank", "state bank", "hdfc", "icici", "sbi",
        "government", "ministry", "income tax", "tax department", "irs",
        "courier", "delivery agent", "dhl", "fedex", "ups", "post office",
        "amazon", "flipkart", "ebay", "paypal",
        "facebook", "instagram", "whatsapp", "twitter",
        "customer support", "helpdesk", "tech support",
        "verified account", "official notice",
    ],
}

PRIZE_REWARD_RULES = {
    "label": "Prize / Reward Language",
    "detail": "The message promises unexpected prizes or rewards — a classic social engineering lure.",
    "score": 10,
    "max_score": 20,
    "keywords": [
        "congratulations", "you have won", "you've won", "you are selected",
        "lucky winner", "cash prize", "gift card", "gift voucher",
        "free iphone", "free laptop", "free gift",
        "claim your prize", "redeem now", "reward points",
        "lucky draw", "sweepstakes",
    ],
}

# ---------------------------------------------------------------------------
# URL Analysis
# ---------------------------------------------------------------------------

# Common URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.io", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
    "adf.ly", "lnkd.in", "tiny.cc", "shorte.st",
}

# Suspicious keywords often appearing in phishing domains/paths
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "paypal", "amazon", "apple", "microsoft",
    "support", "password", "recover", "unlock", "validate",
    "free", "prize", "reward", "winner", "click", "urgent",
]


def analyze_url(url: str) -> dict:
    """
    Analyses a URL string for suspicious characteristics WITHOUT visiting it.

    Returns a dict with:
        score       : int  — points to add to the total risk score
        indicators  : list — human-readable findings
    """
    indicators = []
    score = 0

    if not url or not url.strip():
        return {"score": 0, "indicators": []}

    raw_url = url.strip()

    # --- 1. Check for HTTPS vs HTTP ---
    if raw_url.lower().startswith("http://"):
        indicators.append("URL uses HTTP (not HTTPS) — data is transmitted unencrypted.")
        score += 10
    elif not raw_url.lower().startswith("https://"):
        indicators.append("URL does not begin with https:// — scheme is missing or unusual.")
        score += 8

    # --- 2. Strip scheme for further analysis ---
    clean = re.sub(r'^https?://', '', raw_url, flags=re.IGNORECASE)
    # Remove trailing path for domain extraction
    domain_part = clean.split("/")[0].split("?")[0].split("#")[0].lower()

    # --- 3. IP address used as domain ---
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    )
    if ip_pattern.match(domain_part):
        indicators.append("Domain is a raw IP address — legitimate sites use named domains.")
        score += 20

    # --- 4. URL shortener ---
    base_domain = domain_part.lstrip("www.")
    if base_domain in URL_SHORTENERS:
        indicators.append(f"URL uses a shortening service ({base_domain}) — the real destination is hidden.")
        score += 15

    # --- 5. Excessive subdomains (more than 2 dots in domain) ---
    if domain_part.count(".") >= 3:
        indicators.append("Domain has an unusual number of subdomains — often used to disguise the real domain.")
        score += 10

    # --- 6. Suspicious keywords in URL ---
    full_lower = raw_url.lower()
    found_url_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in full_lower]
    if found_url_keywords:
        indicators.append(
            f"URL contains suspicious keywords: {', '.join(found_url_keywords[:5])}."
        )
        score += min(len(found_url_keywords) * 4, 16)

    # --- 7. Unusually long URL ---
    if len(raw_url) > 200:
        indicators.append("URL is unusually long — phishing URLs often use long strings to confuse users.")
        score += 8

    # --- 8. Unusual characters (encoded characters, @, multiple slashes) ---
    if "@" in raw_url:
        indicators.append("URL contains '@' — this can redirect to a different site than it appears.")
        score += 12
    if "%2F" in raw_url or "%40" in raw_url:
        indicators.append("URL contains encoded characters (%) — can be used to disguise the true destination.")
        score += 8
    if re.search(r'\/\/', clean):
        indicators.append("URL contains a double-slash in the path — an unusual structure.")
        score += 5

    return {"score": min(score, 30), "indicators": indicators}


# ---------------------------------------------------------------------------
# Text Analysis Helpers
# ---------------------------------------------------------------------------

def check_category(text_lower: str, rule: dict) -> dict:
    """
    Checks a lower-cased message against a single rule category.

    Returns:
        found    : bool
        score    : int   — capped at rule["max_score"]
        keywords : list  — matched keywords
    """
    matched = []
    for keyword in rule["keywords"]:
        # Use word-boundary-aware matching to avoid partial matches
        # e.g. "pin" should not match "pinned"
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, text_lower):
            matched.append(keyword)

    if not matched:
        return {"found": False, "score": 0, "keywords": []}

    raw_score = len(matched) * rule["score"]
    capped_score = min(raw_score, rule["max_score"])

    return {"found": True, "score": capped_score, "keywords": matched}


def analyze_message(message: str) -> dict:
    """
    Runs all text-based detection rules against the submitted message.

    Returns:
        total_score : int
        indicators  : list of dicts  — each triggered category with details
    """
    if not message or not message.strip():
        return {"total_score": 0, "indicators": []}

    text_lower = message.lower()
    total_score = 0
    indicators = []

    all_rules = [
        URGENCY_RULES,
        SENSITIVE_INFO_RULES,
        FINANCIAL_RULES,
        THREATENING_RULES,
        IMPERSONATION_RULES,
        PRIZE_REWARD_RULES,
    ]

    for rule in all_rules:
        result = check_category(text_lower, rule)
        if result["found"]:
            total_score += result["score"]
            indicators.append({
                "category": rule["label"],
                "detail": rule["detail"],
                "matched_keywords": result["keywords"][:5],  # show at most 5 examples
                "score_contribution": result["score"],
            })

    return {"total_score": total_score, "indicators": indicators}


# ---------------------------------------------------------------------------
# Risk Scoring & Level
# ---------------------------------------------------------------------------

def calculate_risk_score(message_score: int, url_score: int) -> int:
    """
    Combines message and URL scores and clamps the result to 0–100.

    The URL score is weighted slightly lower (80%) because URL analysis
    alone may produce false positives without message context.
    """
    combined = message_score + int(url_score * 0.8)
    return max(0, min(100, combined))


def determine_risk_level(score: int) -> str:
    """
    Maps a numeric score to a human-readable risk level.

    Thresholds:
        0  – 29  →  LOW
        30 – 59  →  MEDIUM
        60 – 100 →  HIGH
    """
    if score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


# ---------------------------------------------------------------------------
# Explanation & Recommendations
# ---------------------------------------------------------------------------

def build_explanation(
    risk_level: str,
    risk_score: int,
    message_indicators: list,
    url_indicators: list,
) -> str:
    """Produces a plain-language explanation of the risk assessment."""

    total_cats = len(message_indicators) + (1 if url_indicators else 0)

    if risk_level == "HIGH":
        intro = (
            f"This message received a HIGH risk score of {risk_score}/100. "
            f"It triggered {total_cats} warning categor{'y' if total_cats == 1 else 'ies'}. "
            "Multiple strong indicators of a scam or phishing attempt were detected. "
            "Treat this message with extreme caution."
        )
    elif risk_level == "MEDIUM":
        intro = (
            f"This message received a MEDIUM risk score of {risk_score}/100. "
            f"It triggered {total_cats} warning categor{'y' if total_cats == 1 else 'ies'}. "
            "Some indicators associated with scams or phishing were found. "
            "Verify the sender independently before taking any action."
        )
    else:
        intro = (
            f"This message received a LOW risk score of {risk_score}/100. "
            "Few or no commonly observed scam indicators were found. "
            "However, no tool can guarantee a message is entirely safe — "
            "always verify unexpected requests through official channels."
        )

    parts = [intro]

    if message_indicators:
        parts.append("Detected message indicators:")
        for ind in message_indicators:
            kw_str = ", ".join(f'"{k}"' for k in ind["matched_keywords"])
            parts.append(f"  • {ind['category']}: found keywords {kw_str}.")

    if url_indicators:
        parts.append("Detected URL indicators:")
        for ind in url_indicators:
            parts.append(f"  • {ind}")

    return " ".join(parts)


def generate_recommendations(risk_level: str, message_indicators: list) -> list:
    """Returns a list of recommended actions based on the risk assessment."""

    category_labels = [ind["category"] for ind in message_indicators]

    recs = []

    # Universal recommendations
    recs.append("Do NOT click any links in the message without first verifying the sender.")
    recs.append("Do NOT share passwords, OTPs, PINs, CVVs, or any financial credentials.")

    if risk_level == "HIGH":
        recs.append("Consider this message highly suspicious — do not respond or act on it.")
        recs.append("Report this message to your email provider or mobile carrier as spam/phishing.")
        recs.append("If you have already interacted with this message, contact your bank or relevant institution immediately.")

    elif risk_level == "MEDIUM":
        recs.append("Contact the sender through an independently verified phone number or official website — not via the details in this message.")
        recs.append("Search for the claimed organisation's official contact details separately.")

    # Category-specific recommendations
    if "Sensitive Information Request" in category_labels:
        recs.append("Legitimate organisations (banks, government bodies) will NEVER ask for OTPs, PINs, or passwords via SMS or email.")

    if "Threatening / Fear-Inducing Language" in category_labels:
        recs.append("Threats of legal action or account suspension via unsolicited messages are a classic pressure tactic — verify any such claim through official channels.")

    if "Prize / Reward Language" in category_labels:
        recs.append("Unsolicited prize notifications are almost always fraudulent. Legitimate lotteries do not contact winners via SMS or email.")

    if "Urgency / Pressure Tactics" in category_labels:
        recs.append("Take time to think. Scammers create artificial urgency so that you act before you think critically.")

    recs.append("If in doubt, seek advice from a trusted person or your national cybercrime helpline before responding.")

    return recs


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ScamShield",
    description="Defensive cybersecurity risk assessment for suspicious messages and URLs.",
    version="1.0.0",
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Adds basic security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """
    Analyses a submitted message and optional URL for scam/phishing indicators.

    Returns a structured risk assessment. Input is processed in memory only
    and is NOT stored or logged.
    """
    # Run message analysis
    msg_result = analyze_message(request.message)

    # Run URL analysis
    url_result = analyze_url(request.url or "")

    # Calculate combined score
    risk_score = calculate_risk_score(msg_result["total_score"], url_result["score"])
    risk_level = determine_risk_level(risk_score)

    # Combine all indicators
    all_indicators = []
    for ind in msg_result["indicators"]:
        all_indicators.append({
            "source": "message",
            "category": ind["category"],
            "detail": ind["detail"],
            "matched_keywords": ind["matched_keywords"],
            "score_contribution": ind["score_contribution"],
        })
    for url_ind in url_result["indicators"]:
        all_indicators.append({
            "source": "url",
            "category": "URL Analysis",
            "detail": url_ind,
            "matched_keywords": [],
            "score_contribution": 0,
        })

    explanation = build_explanation(
        risk_level, risk_score,
        msg_result["indicators"],
        url_result["indicators"],
    )

    recommendations = generate_recommendations(risk_level, msg_result["indicators"])

    return AnalyzeResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        detected_indicators=all_indicators,
        explanation=explanation,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Frontend HTML
# ---------------------------------------------------------------------------

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ScamShield — Risk Assessment Tool</title>
<style>
/* ============================================================
   BASE / RESET
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 15px; scroll-behavior: smooth; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0d1117;
  color: #c9d1d9;
  min-height: 100vh;
  line-height: 1.6;
}
a { color: #58a6ff; }

/* ============================================================
   LAYOUT
   ============================================================ */
.app-wrapper {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

/* ---- Header ---- */
header {
  background: #161b22;
  border-bottom: 1px solid #30363d;
  padding: 0 2rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  height: 60px;
  position: sticky;
  top: 0;
  z-index: 100;
}
.logo-mark {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, #1f6feb, #388bfd);
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.2rem; font-weight: 700; color: #fff;
  flex-shrink: 0;
}
header h1 {
  font-size: 1.15rem;
  font-weight: 700;
  color: #f0f6fc;
  letter-spacing: 0.5px;
}
header .tagline {
  margin-left: auto;
  font-size: 0.8rem;
  color: #8b949e;
  display: none;
}
@media(min-width:600px){ header .tagline { display: block; } }

/* ---- Main content ---- */
main {
  flex: 1;
  max-width: 960px;
  width: 100%;
  margin: 0 auto;
  padding: 2rem 1.5rem;
}

/* ============================================================
   PRIVACY NOTICE
   ============================================================ */
.privacy-notice {
  background: #161b22;
  border: 1px solid #30363d;
  border-left: 4px solid #388bfd;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  font-size: 0.82rem;
  color: #8b949e;
  margin-bottom: 1.5rem;
}
.privacy-notice strong { color: #c9d1d9; }

/* ============================================================
   INPUT CARD
   ============================================================ */
.card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.card-title {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: #8b949e;
  margin-bottom: 1rem;
}
label {
  display: block;
  font-size: 0.85rem;
  color: #c9d1d9;
  margin-bottom: 0.4rem;
  font-weight: 500;
}
textarea, input[type="url"] {
  width: 100%;
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  color: #c9d1d9;
  font-family: inherit;
  font-size: 0.9rem;
  padding: 0.65rem 0.85rem;
  resize: vertical;
  transition: border-color 0.15s;
  outline: none;
}
textarea { min-height: 120px; }
textarea:focus, input[type="url"]:focus {
  border-color: #388bfd;
  box-shadow: 0 0 0 3px rgba(56,139,253,0.12);
}

.field-row { margin-bottom: 1.1rem; }
.char-count {
  font-size: 0.75rem;
  color: #6e7681;
  text-align: right;
  margin-top: 0.25rem;
}
.char-count.warn { color: #f0883e; }

/* ---- Buttons ---- */
.btn-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-top: 0.25rem;
}
button {
  cursor: pointer;
  border: none;
  border-radius: 6px;
  font-family: inherit;
  font-size: 0.88rem;
  font-weight: 600;
  padding: 0.6rem 1.4rem;
  transition: opacity 0.15s, background 0.15s;
}
.btn-primary {
  background: #1f6feb;
  color: #fff;
}
.btn-primary:hover { background: #388bfd; }
.btn-primary:disabled { opacity: 0.45; cursor: not-allowed; }
.btn-secondary {
  background: #21262d;
  color: #c9d1d9;
  border: 1px solid #30363d;
}
.btn-secondary:hover { background: #30363d; }

/* ---- Example Messages ---- */
.examples-section { margin-top: 1rem; }
.examples-title {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: #8b949e;
  margin-bottom: 0.6rem;
}
.examples-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.example-btn {
  background: #21262d;
  border: 1px solid #30363d;
  border-radius: 20px;
  color: #8b949e;
  font-size: 0.78rem;
  font-weight: 500;
  padding: 0.3rem 0.85rem;
  cursor: pointer;
  transition: background 0.15s, color 0.15s, border-color 0.15s;
}
.example-btn:hover {
  background: #30363d;
  color: #c9d1d9;
  border-color: #58a6ff;
}

/* ============================================================
   RESULTS PANEL
   ============================================================ */
#results { display: none; }

/* ---- Score Card ---- */
.score-card {
  display: grid;
  grid-template-columns: auto 1fr;
  align-items: center;
  gap: 1.5rem;
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.score-dial {
  width: 90px; height: 90px;
  border-radius: 50%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border: 4px solid #30363d;
  flex-shrink: 0;
}
.score-dial .score-num {
  font-size: 1.8rem;
  font-weight: 700;
  line-height: 1;
}
.score-dial .score-sub {
  font-size: 0.65rem;
  color: #8b949e;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.score-card .risk-meta { }
.score-card .risk-label {
  font-size: 0.78rem;
  color: #8b949e;
  text-transform: uppercase;
  letter-spacing: 1px;
  font-weight: 600;
}
.risk-badge {
  display: inline-block;
  border-radius: 20px;
  font-size: 0.85rem;
  font-weight: 700;
  padding: 0.3rem 1rem;
  letter-spacing: 0.5px;
  margin: 0.4rem 0;
}
.badge-LOW    { background: #1a4a1a; color: #56d364; border: 1px solid #2ea043; }
.badge-MEDIUM { background: #4a3000; color: #f0883e; border: 1px solid #9e6a03; }
.badge-HIGH   { background: #4a1515; color: #f85149; border: 1px solid #da3633; }

.score-dial.LOW    { border-color: #2ea043; }
.score-dial.MEDIUM { border-color: #9e6a03; }
.score-dial.HIGH   { border-color: #da3633; }
.score-dial.LOW    .score-num { color: #56d364; }
.score-dial.MEDIUM .score-num { color: #f0883e; }
.score-dial.HIGH   .score-num { color: #f85149; }

.score-disclaimer {
  font-size: 0.78rem;
  color: #6e7681;
  font-style: italic;
  margin-top: 0.3rem;
}

/* ---- Indicators ---- */
.indicators-card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.indicator-item {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: 0.8rem 1rem;
  margin-bottom: 0.65rem;
}
.indicator-item:last-child { margin-bottom: 0; }
.indicator-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.3rem;
}
.indicator-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #f85149;
  flex-shrink: 0;
}
.indicator-dot.url { background: #f0883e; }
.indicator-title {
  font-size: 0.88rem;
  font-weight: 600;
  color: #f0f6fc;
}
.indicator-detail {
  font-size: 0.82rem;
  color: #8b949e;
  margin-bottom: 0.3rem;
}
.keyword-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.3rem;
}
.keyword-chip {
  background: #21262d;
  border: 1px solid #30363d;
  border-radius: 4px;
  font-size: 0.75rem;
  padding: 0.15rem 0.5rem;
  color: #8b949e;
  font-family: 'Courier New', monospace;
}
.no-indicators {
  font-size: 0.88rem;
  color: #8b949e;
  font-style: italic;
}

/* ---- Explanation ---- */
.explanation-card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.explanation-text {
  font-size: 0.88rem;
  color: #c9d1d9;
  line-height: 1.7;
  white-space: pre-wrap;
}

/* ---- Recommendations ---- */
.recs-card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.rec-item {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 0.65rem;
  font-size: 0.88rem;
  color: #c9d1d9;
  align-items: flex-start;
}
.rec-item:last-child { margin-bottom: 0; }
.rec-icon {
  flex-shrink: 0;
  width: 20px; height: 20px;
  background: #1a4a1a;
  border: 1px solid #2ea043;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.7rem;
  color: #56d364;
  margin-top: 2px;
}

/* ---- Loading spinner ---- */
#loading {
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  gap: 1rem;
}
.spinner {
  width: 40px; height: 40px;
  border: 3px solid #30363d;
  border-top-color: #388bfd;
  border-radius: 50%;
  animation: spin 0.75s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
#loading p { font-size: 0.9rem; color: #8b949e; }

/* ---- Error message ---- */
#error-msg {
  display: none;
  background: #4a1515;
  border: 1px solid #da3633;
  border-radius: 8px;
  padding: 0.9rem 1rem;
  font-size: 0.88rem;
  color: #f85149;
  margin-bottom: 1.5rem;
}

/* ============================================================
   FOOTER
   ============================================================ */
footer {
  background: #161b22;
  border-top: 1px solid #30363d;
  padding: 1rem 2rem;
  text-align: center;
  font-size: 0.78rem;
  color: #6e7681;
}
</style>
</head>
<body>
<div class="app-wrapper">

  <!-- ========== HEADER ========== -->
  <header>
    <div class="logo-mark">S</div>
    <h1>ScamShield</h1>
    <span class="tagline">Defensive Phishing &amp; Scam Risk Assessment</span>
  </header>

  <!-- ========== MAIN ========== -->
  <main>

    <!-- Privacy Notice -->
    <div class="privacy-notice">
      <strong>Privacy Notice:</strong>
      This tool processes your input <strong>locally on this server</strong> — no submitted messages are stored,
      logged, or transmitted to third parties. Do not enter real passwords, OTPs, or financial credentials.
      This is an educational risk assessment tool, not a definitive fraud detector.
    </div>

    <!-- Input Card -->
    <div class="card">
      <div class="card-title">Submit Message for Analysis</div>

      <div class="field-row">
        <label for="msg-input">Suspicious Message</label>
        <textarea id="msg-input" placeholder="Paste a suspicious SMS, email, or message here..." maxlength="10000"></textarea>
        <div class="char-count" id="msg-count">0 / 10 000</div>
      </div>

      <div class="field-row">
        <label for="url-input">URL (optional)</label>
        <input type="url" id="url-input" placeholder="https://example.com/verify-account" maxlength="2000"/>
      </div>

      <div class="btn-row">
        <button class="btn-primary" id="analyze-btn" onclick="runAnalysis()">Analyze Message</button>
        <button class="btn-secondary" onclick="clearAll()">Clear / Reset</button>
      </div>

      <!-- Example messages -->
      <div class="examples-section">
        <div class="examples-title">Load an example</div>
        <div class="examples-grid" id="examples-grid"></div>
      </div>
    </div>

    <!-- Loading -->
    <div id="loading">
      <div class="spinner"></div>
      <p>Analysing message…</p>
    </div>

    <!-- Error -->
    <div id="error-msg"></div>

    <!-- Results -->
    <div id="results">

      <!-- Score Card -->
      <div class="score-card" id="score-card">
        <div class="score-dial" id="score-dial">
          <span class="score-num" id="score-num">—</span>
          <span class="score-sub">/ 100</span>
        </div>
        <div class="risk-meta">
          <div class="risk-label">Risk Level</div>
          <div id="risk-badge" class="risk-badge">—</div>
          <div class="score-disclaimer">
            This is a risk assessment, not a confirmed fraud verdict.
            Scores are based on pattern matching and may produce false positives.
          </div>
        </div>
      </div>

      <!-- Detected Indicators -->
      <div class="indicators-card">
        <div class="card-title">Detected Indicators</div>
        <div id="indicators-list"></div>
      </div>

      <!-- Explanation -->
      <div class="explanation-card">
        <div class="card-title">Analysis Explanation</div>
        <pre class="explanation-text" id="explanation-text"></pre>
      </div>

      <!-- Recommendations -->
      <div class="recs-card">
        <div class="card-title">Recommended Actions</div>
        <div id="recs-list"></div>
      </div>

    </div>
    <!-- /results -->

  </main>

  <!-- ========== FOOTER ========== -->
  <footer>
    ScamShield — Cybersecurity Education Project &nbsp;|&nbsp;
    For educational use only. Not a certified fraud detection service. &nbsp;|&nbsp;
    <a href="https://www.ncsc.gov.uk/guidance/phishing" target="_blank" rel="noopener noreferrer">Learn more about phishing</a>
  </footer>

</div><!-- /app-wrapper -->

<script>
/* =============================================================
   EXAMPLE MESSAGES
   ============================================================= */
const EXAMPLES = [
  {
    label: "Banking Scam",
    message: "URGENT: Your SBI bank account has been suspended due to suspicious activity. Verify your account immediately by clicking this link or your account will be permanently blocked. Enter your card number, PIN, and OTP to confirm your identity.",
    url: "http://sbi-verify-account.xyz/login"
  },
  {
    label: "Prize Scam",
    message: "Congratulations! You are the lucky winner of our Rs 10 Lakh cash prize lottery! You have been selected. Claim your reward now by providing your bank account number and CVV. Act within 24 hours or forfeit your prize!",
    url: ""
  },
  {
    label: "Delivery Scam",
    message: "Your Amazon package #A7845 is on hold. A customs fee of Rs 199 is due. Pay now via UPI to avoid return. Click here to pay: bit.ly/amzn-fee",
    url: "https://bit.ly/amzn-fee"
  },
  {
    label: "Job Scam",
    message: "Work from home opportunity! Earn Rs 5000 per day. No experience needed. Transfer Rs 500 as registration fee to our bank account to start. Limited seats available. Register now!",
    url: ""
  },
  {
    label: "Tax Scam",
    message: "Income Tax Department Notice: A tax refund of Rs 15,840 is pending for your PAN. Verify your bank details and Aadhaar number within 48 hours to receive the refund or face a penalty.",
    url: ""
  },
  {
    label: "Legitimate Message",
    message: "Hi, this is a reminder that your appointment with Dr. Sharma is scheduled for tomorrow at 10:30 AM at City Hospital. Please call 011-2345-6789 to reschedule if needed.",
    url: ""
  },
  {
    label: "Suspicious URL",
    message: "Please log in to your account.",
    url: "http://192.168.1.1/paypal-login/verify?user=test"
  },
  {
    label: "Account Verification Scam",
    message: "Your WhatsApp account will be deactivated in 24 hours. To keep your account active, verify your phone number and OTP at the link below. Failure to respond will result in permanent suspension.",
    url: ""
  },
];

/* Render example buttons */
const grid = document.getElementById("examples-grid");
EXAMPLES.forEach((ex, i) => {
  const btn = document.createElement("button");
  btn.className = "example-btn";
  btn.textContent = ex.label;
  btn.onclick = () => loadExample(i);
  grid.appendChild(btn);
});

function loadExample(index) {
  const ex = EXAMPLES[index];
  document.getElementById("msg-input").value = ex.message;
  document.getElementById("url-input").value = ex.url || "";
  updateCharCount();
  // Clear any previous results
  hideResults();
}

/* =============================================================
   CHARACTER COUNT
   ============================================================= */
const msgInput = document.getElementById("msg-input");
const msgCount = document.getElementById("msg-count");

function updateCharCount() {
  const len = msgInput.value.length;
  msgCount.textContent = len.toLocaleString() + " / 10 000";
  msgCount.classList.toggle("warn", len > 9000);
}
msgInput.addEventListener("input", updateCharCount);

/* =============================================================
   MAIN ANALYSIS
   ============================================================= */
async function runAnalysis() {
  const message = msgInput.value.trim();
  const url = document.getElementById("url-input").value.trim();

  // Client-side validation
  if (!message) {
    showError("Please enter a message to analyse.");
    return;
  }

  hideResults();
  hideError();
  showLoading(true);
  setAnalyzeDisabled(true);

  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message, url: url || null })
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `Server returned status ${resp.status}`);
    }

    const data = await resp.json();
    renderResults(data);

  } catch (err) {
    showError("Analysis failed: " + (err.message || "Unknown error. Please try again."));
  } finally {
    showLoading(false);
    setAnalyzeDisabled(false);
  }
}

/* =============================================================
   RENDER RESULTS
   ============================================================= */
function renderResults(data) {
  /* Score dial */
  const dial = document.getElementById("score-dial");
  dial.className = "score-dial " + data.risk_level;
  document.getElementById("score-num").textContent = data.risk_score;

  /* Risk badge */
  const badge = document.getElementById("risk-badge");
  badge.textContent = data.risk_level + " RISK";
  badge.className = "risk-badge badge-" + data.risk_level;

  /* Indicators */
  const indList = document.getElementById("indicators-list");
  indList.innerHTML = "";
  if (!data.detected_indicators || data.detected_indicators.length === 0) {
    indList.innerHTML = '<p class="no-indicators">No strong indicators detected in this message.</p>';
  } else {
    data.detected_indicators.forEach(ind => {
      const item = document.createElement("div");
      item.className = "indicator-item";

      const dotClass = ind.source === "url" ? "indicator-dot url" : "indicator-dot";
      const kws = ind.matched_keywords && ind.matched_keywords.length
        ? "<div class='keyword-chips'>" +
          ind.matched_keywords.map(k => `<span class="keyword-chip">${escHtml(k)}</span>`).join("") +
          "</div>"
        : "";

      item.innerHTML = `
        <div class="indicator-header">
          <div class="${dotClass}"></div>
          <div class="indicator-title">${escHtml(ind.category)}</div>
        </div>
        <div class="indicator-detail">${escHtml(ind.detail)}</div>
        ${kws}
      `;
      indList.appendChild(item);
    });
  }

  /* Explanation */
  // explanation is plain text from server; display as-is (pre-wrap handles formatting)
  document.getElementById("explanation-text").textContent = data.explanation;

  /* Recommendations */
  const recsList = document.getElementById("recs-list");
  recsList.innerHTML = "";
  (data.recommendations || []).forEach(rec => {
    const item = document.createElement("div");
    item.className = "rec-item";
    item.innerHTML = `<div class="rec-icon">&#10003;</div><div>${escHtml(rec)}</div>`;
    recsList.appendChild(item);
  });

  document.getElementById("results").style.display = "block";

  // Scroll to results smoothly
  document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* =============================================================
   UTILITY FUNCTIONS
   ============================================================= */
function escHtml(str) {
  /* Safely escape user-supplied strings before inserting into innerHTML */
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function clearAll() {
  document.getElementById("msg-input").value = "";
  document.getElementById("url-input").value = "";
  updateCharCount();
  hideResults();
  hideError();
}

function hideResults() {
  document.getElementById("results").style.display = "none";
}

function hideError() {
  const e = document.getElementById("error-msg");
  e.style.display = "none";
  e.textContent = "";
}

function showError(msg) {
  const e = document.getElementById("error-msg");
  e.textContent = msg;
  e.style.display = "block";
}

function showLoading(show) {
  document.getElementById("loading").style.display = show ? "flex" : "none";
}

function setAnalyzeDisabled(disabled) {
  document.getElementById("analyze-btn").disabled = disabled;
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serves the ScamShield frontend HTML page."""
    return HTMLResponse(content=HTML_PAGE)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
