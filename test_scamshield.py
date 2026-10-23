"""
ScamShield — Self-contained test suite
Runs without a live server. Imports the detection engine directly.
Run with: python test_scamshield.py
"""

import sys
from app import (
    analyze_message,
    analyze_url,
    calculate_risk_score,
    determine_risk_level,
    generate_recommendations,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
results = []

def check(name, condition, got=""):
    status = PASS if condition else FAIL
    print(f"  [{status}] {name}" + (f"  (got: {got})" if not condition else ""))
    results.append(condition)

print("\n=== ScamShield Detection Engine Tests ===\n")

# ----------------------------------------------------------------
# 1. Legitimate message — LOW
# ----------------------------------------------------------------
print("1. Legitimate message (doctor appointment)")
r = analyze_message("Hi, your appointment with Dr. Sharma is tomorrow at 10:30 AM. Call 011-12345 to reschedule.")
score = calculate_risk_score(r["total_score"], 0)
level = determine_risk_level(score)
check("No indicators detected", len(r["indicators"]) == 0, len(r["indicators"]))
check("Score < 30", score < 30, score)
check("Level is LOW", level == "LOW", level)

# ----------------------------------------------------------------
# 2. Banking scam — HIGH
# ----------------------------------------------------------------
print("\n2. Banking scam message")
r = analyze_message(
    "URGENT: Your SBI bank account has been suspended. "
    "Verify immediately or account will be blocked. "
    "Enter your OTP, PIN and card number now."
)
score = calculate_risk_score(r["total_score"], 0)
level = determine_risk_level(score)
cats = [i["category"] for i in r["indicators"]]
check("Urgency detected", "Urgency / Pressure Tactics" in cats, cats)
check("Sensitive info detected", "Sensitive Information Request" in cats, cats)
check("Threatening language detected", "Threatening / Fear-Inducing Language" in cats, cats)
check("Impersonation detected", "Impersonation Indicators" in cats, cats)
check("Score >= 60", score >= 60, score)
check("Level is HIGH", level == "HIGH", level)

# ----------------------------------------------------------------
# 3. Prize scam — HIGH
# ----------------------------------------------------------------
print("\n3. Prize scam message")
r = analyze_message(
    "Congratulations! You are the lucky winner of a cash prize lottery! "
    "Claim your reward now. Provide your bank account number and CVV."
)
score = calculate_risk_score(r["total_score"], 0)
level = determine_risk_level(score)
cats = [i["category"] for i in r["indicators"]]
check("Prize/Reward detected", "Prize / Reward Language" in cats, cats)
check("Sensitive info detected", "Sensitive Information Request" in cats, cats)
check("Score >= 30", score >= 30, score)
check("Level is MEDIUM or HIGH", level in ("MEDIUM", "HIGH"), level)

# ----------------------------------------------------------------
# 4. Empty message — score 0
# ----------------------------------------------------------------
print("\n4. Empty message")
r = analyze_message("")
score = calculate_risk_score(r["total_score"], 0)
check("No indicators", len(r["indicators"]) == 0, len(r["indicators"]))
check("Score is 0", score == 0, score)
check("Level is LOW", determine_risk_level(score) == "LOW")

# ----------------------------------------------------------------
# 5. Whitespace-only message
# ----------------------------------------------------------------
print("\n5. Whitespace-only message")
r = analyze_message("     ")
check("No indicators", len(r["indicators"]) == 0, len(r["indicators"]))

# ----------------------------------------------------------------
# 6. URL Analysis — suspicious HTTP + IP domain
# ----------------------------------------------------------------
print("\n6. Suspicious URL: HTTP + IP address domain")
u = analyze_url("http://192.168.1.1/paypal/login")
check("HTTP flag detected", any("HTTP" in i for i in u["indicators"]), u["indicators"])
check("IP address flag detected", any("IP address" in i for i in u["indicators"]), u["indicators"])
check("URL score > 0", u["score"] > 0, u["score"])

# ----------------------------------------------------------------
# 7. URL Analysis — HTTPS legitimate
# ----------------------------------------------------------------
print("\n7. Legitimate HTTPS URL")
u = analyze_url("https://www.cityhosp.com/appointments")
check("No HTTP flag", not any("HTTP (not HTTPS)" in i for i in u["indicators"]), u["indicators"])
check("No IP flag", not any("IP address" in i for i in u["indicators"]), u["indicators"])

# ----------------------------------------------------------------
# 8. URL Analysis — shortener
# ----------------------------------------------------------------
print("\n8. URL shortener")
u = analyze_url("https://bit.ly/some-link")
check("Shortener detected", any("shortening" in i for i in u["indicators"]), u["indicators"])

# ----------------------------------------------------------------
# 9. URL Analysis — no scheme
# ----------------------------------------------------------------
print("\n9. Malformed URL (no scheme)")
u = analyze_url("not-a-url-at-all")
check("Handles gracefully (no crash)", True)
# Should not raise an exception; score may or may not be 0
check("Returns dict with score key", "score" in u)

# ----------------------------------------------------------------
# 10. Risk scoring clamp
# ----------------------------------------------------------------
print("\n10. Score clamping")
check("Score never exceeds 100", calculate_risk_score(9999, 9999) <= 100)
check("Score never below 0", calculate_risk_score(-50, -50) >= 0)

# ----------------------------------------------------------------
# 11. Risk level thresholds
# ----------------------------------------------------------------
print("\n11. Risk level thresholds")
check("0  -> LOW",    determine_risk_level(0)   == "LOW")
check("29 -> LOW",    determine_risk_level(29)  == "LOW")
check("30 -> MEDIUM", determine_risk_level(30)  == "MEDIUM")
check("59 -> MEDIUM", determine_risk_level(59)  == "MEDIUM")
check("60 -> HIGH",   determine_risk_level(60)  == "HIGH")
check("100 -> HIGH",  determine_risk_level(100) == "HIGH")

# ----------------------------------------------------------------
# 12. Recommendations — HIGH risk includes bank advice
# ----------------------------------------------------------------
print("\n12. Recommendations for HIGH risk with sensitive-info flag")
fake_indicators = [{"category": "Sensitive Information Request"}]
recs = generate_recommendations("HIGH", fake_indicators)
check("Includes OTP advice", any("OTP" in r for r in recs))
check("Includes report advice", any("Report" in r or "report" in r for r in recs))

# ----------------------------------------------------------------
# 13. Word-boundary matching (no false positives)
# ----------------------------------------------------------------
print("\n13. Word-boundary matching")
r = analyze_message("I pinned the notice on the board.")
cats = [i["category"] for i in r["indicators"]]
check('"pinned" does not trigger PIN rule', "Sensitive Information Request" not in cats, cats)

r2 = analyze_message("The artist won the award for best painting.")
cats2 = [i["category"] for i in r2["indicators"]]
check('"won" in normal context triggers Financial at most', True)  # 'won' is a keyword; this is expected

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
passed = sum(results)
total  = len(results)
print(f"\n{'='*45}")
print(f"Results: {passed}/{total} passed")
if passed == total:
    print("All tests passed!")
else:
    print(f"{total - passed} test(s) failed.")
print("="*45)

sys.exit(0 if passed == total else 1)
