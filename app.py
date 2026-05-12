from flask  import Flask, render_template, request, make_response
import re
from datetime import datetime

app = Flask(__name__)

# Trusted domains (explicit allowlist)
TRUSTED_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "google.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "zomato.com,",
    "youtube.com",
    "swiggy.com",
    "uudoon.in",
    "crunchyroll.com",
    "whatsapp.in"
]

# URL shorteners (domains only)
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly"
]

URGENCY_WORDS = [
    "urgent", "verify immediately", "account suspended",
    "act now", "limited time", "immediately"
]

CREDENTIAL_WORDS = [
    "password", "otp", "bank details", "account", 
    "credit card", "login now", "pin"
]

THREAT_WORDS = [
    "will be closed", "legal action", "blocked permanently",
    "security breach"
]


def contains_domain(domain, text):
    """
    Matches domain with or without protocol.
    Examples matched:
    - bit.ly/abc
    - https://bit.ly/abc
    - http://www.bit.ly/abc
    """
    return re.search(
        rf"(https?://)?(www\.)?{re.escape(domain)}(/|$)",
        text
    )


def analyze_input(user_input):
    score = 0
    reasons = []     # Trust indicators
    warnings = []    # Issues
    tips = []
    techniques = []

    text = user_input.lower().strip()

    # ---------- TRUSTED DOMAIN CHECK ----------
    for domain in TRUSTED_DOMAINS:
        if re.search(rf"^https://(www\.)?{re.escape(domain)}(/|$)", text):
            return (
                "Safe",
                0,
                95,
                ["Trusted and verified domain detected"],
                [],
                ["Continue using official websites for safety."],
                ["Verified legitimate source"]
            )

    # ---------- URL SHORTENER CHECK (FIXED) ----------
    shortener_found = False
    for shortener in URL_SHORTENERS:
        if contains_domain(shortener, text):
            shortener_found = True
            score += 5
            warnings.append("URL shortener detected")
            tips.append("URL shorteners hide the real destination.")
            techniques.append("Link obfuscation")
            break

    # ---------- OTHER URL CHECKS ----------
    if re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", text):
        score += 3
        warnings.append("IP-based URL detected")
        tips.append("Legitimate websites rarely use raw IP addresses.")
        techniques.append("Malicious link usage")

    if text.startswith("http://"):
        score += 2
        warnings.append("Unsecured HTTP link detected")
        tips.append("Avoid entering sensitive data on HTTP websites.")
        techniques.append("Insecure communication")

    if re.search(r"(paypa1|amaz0n|micr0soft|g00gle)", text):
        score += 3
        warnings.append("Suspicious domain spelling detected")
        tips.append("Attackers use lookalike domains.")
        techniques.append("Domain spoofing")

    # ---------- MESSAGE CHECKS ----------
    for word in URGENCY_WORDS:
        if word in text:
            score += 2
            warnings.append("Urgency language detected")
            tips.append("Urgency is used to pressure users.")
            techniques.append("Urgency-based social engineering")
            break

    for word in CREDENTIAL_WORDS:
        if word in text:
            score += 3
            warnings.append("Credential request detected")
            tips.append("Never share passwords or OTPs.")
            techniques.append("Credential harvesting")
            break

    for word in THREAT_WORDS:
        if word in text:
            score += 2
            warnings.append("Threatening language detected")
            tips.append("Threats are used to scare users.")
            techniques.append("Fear-based manipulation")
            break

    if "verify your account" in text or "verify account" in text:
        score += 2
        warnings.append("Account verification request detected")
        tips.append("Verification requests are common phishing tactics.")
        techniques.append("Account takeover attempt")

    if "verify" in text and ("http://" in text or "https://" in text):
        score += 3
        warnings.append("Suspicious verification link detected")
        tips.append("Fake verification links lead to phishing sites.")
        techniques.append("Credential harvesting")

    if re.search(r"\b(dear user|dear customer)\b", text):
        score += 1
        warnings.append("Generic greeting detected")
        tips.append("Legitimate companies usually address users by name.")

    # ---------- RISK CLASSIFICATION ----------
    if score <= 1:
        risk = "Safe"
    elif score <= 4:
        risk = "Suspicious"
    else:
        risk = "High Risk Phishing"

    confidence = 95 if risk == "Safe" else min(score * 15, 100)

    return (
        risk,
        score,
        confidence,
        reasons,
        warnings,
        tips,
        list(set(techniques))
    )


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        user_input = request.form.get("user_input", "")
        (
            risk,
            score,
            confidence,
            reasons,
            warnings,
            tips,
            techniques
        ) = analyze_input(user_input)

        result = {
            "risk": risk,
            "score": score,
            "confidence": confidence,
            "reasons": reasons,
            "warnings": warnings,
            "tips": tips,
            "techniques": techniques,
            "input": user_input
        }

    return render_template("index.html", result=result)


@app.route("/download", methods=["POST"])
def download_report():
    data = request.form
    content = f"""
PHISHGUARD PHISHING ANALYSIS REPORT
Generated: {datetime.now()}

Input:
{data.get('input')}

Risk Level: {data.get('risk')}
Risk Score: {data.get('score')}
Confidence Level: {data.get('confidence')}%

Warnings:
{data.get('warnings')}

Phishing Techniques:
{data.get('techniques')}

Safety Tips:
{data.get('tips')}
"""

    response = make_response(content)
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_report.txt"
    response.headers["Content-Type"] = "text/plain"
    return response


if __name__ == "__main__":
    app.run(debug=True)
