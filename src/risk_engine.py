import re

from src.predictor import predict_email
from src.email_parser import parse_email
from src.url_analyzer import analyze_url


# =========================================================
# URL EXTRACTION
# =========================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(pattern, text)

    # Remove duplicate URLs
    return list(dict.fromkeys(urls))


# =========================================================
# SECURITY INDICATORS
# =========================================================

def find_indicators(text):

    text = (text or "").lower()

    indicators = []

    # Strong phishing phrases
    strong_patterns = [
        ("password", "Password request detected"),
        ("otp", "OTP request detected"),
        ("one time password", "OTP request detected"),
        ("bank account", "Bank account reference detected"),
        ("credit card", "Credit card reference detected"),
        ("verify your account", "Account verification request"),
        ("confirm your account", "Account confirmation request"),
        ("account suspended", "Account suspension warning"),
        ("account will be closed", "Account closure warning"),
        ("login immediately", "Urgent login request"),
        ("click here immediately", "Urgent click request"),
        ("reset your password", "Password reset request"),
        ("enter your password", "Password entry request"),
        ("provide your otp", "OTP request detected"),
    ]

    for phrase, message in strong_patterns:

        if phrase in text:
            if message not in indicators:
                indicators.append(message)

    # Urgency words
    urgency_words = [
        "urgent",
        "immediately",
        "as soon as possible",
        "action required",
        "act now",
        "limited time",
        "expires today",
        "final warning"
    ]

    urgency_found = False

    for word in urgency_words:

        if word in text:
            urgency_found = True
            break

    if urgency_found:
        indicators.append("Urgency detected")

    # Suspicious prize / money
    money_patterns = [
        "you won",
        "winner",
        "free gift",
        "claim your prize",
        "lottery",
        "cash prize",
        "reward"
    ]

    for word in money_patterns:

        if word in text:
            indicators.append("Prize/reward related content")
            break

    # Generic link language
    link_patterns = [
        "click here",
        "click the link",
        "verify here",
        "login here",
        "open this link"
    ]

    for word in link_patterns:

        if word in text:
            indicators.append("Suspicious link instruction")
            break

    return list(dict.fromkeys(indicators))


# =========================================================
# URL RISK
# =========================================================

def calculate_url_risk(urls):

    if not urls:
        return 0

    highest_risk = 0

    for url in urls:

        try:

            result = analyze_url(url)

            if isinstance(result, dict):

                risk = result.get(
                    "risk_score",
                    result.get("risk", 0)
                )

            else:

                risk = 0

            try:
                risk = float(risk)
            except Exception:
                risk = 0

            highest_risk = max(
                highest_risk,
                risk
            )

        except Exception:

            continue

    return round(highest_risk, 2)


# =========================================================
# FINAL PREDICTION
# =========================================================

def get_final_prediction(
    ml_prediction,
    ml_confidence,
    risk_score,
    indicators,
    url_risk
):

    confidence = float(
        ml_confidence or 0
    )

    indicator_count = len(
        indicators
    )

    indicator_text = " ".join(
        str(item).lower()
        for item in indicators
    )

    # -----------------------------------------------------
    # STRONG PHISHING INDICATORS
    # -----------------------------------------------------

    strong_words = [
        "password",
        "otp",
        "bank",
        "credit card",
        "account suspended",
        "verify your account",
        "confirm your account",
        "login immediately",
        "click here immediately",
        "password reset",
        "password entry"
    ]

    strong_count = 0

    for word in strong_words:

        if word in indicator_text:
            strong_count += 1

    # -----------------------------------------------------
    # VERY HIGH URL RISK
    # -----------------------------------------------------

    if url_risk >= 90:

        return "PHISHING"

    # -----------------------------------------------------
    # HIGH CONFIDENCE + STRONG INDICATORS
    # -----------------------------------------------------

    if (
        ml_prediction == 1
        and confidence >= 90
        and strong_count >= 2
        and risk_score >= 65
    ):

        return "PHISHING"

    # -----------------------------------------------------
    # MULTIPLE STRONG INDICATORS
    # -----------------------------------------------------

    if (
        strong_count >= 3
        and risk_score >= 70
    ):

        return "PHISHING"

    # -----------------------------------------------------
    # MEDIUM RISK
    # -----------------------------------------------------

    if (
        risk_score >= 45
        and indicator_count >= 2
    ):

        return "SUSPICIOUS"

    # -----------------------------------------------------
    # SINGLE INDICATOR
    # -----------------------------------------------------

    if (
        risk_score >= 35
        and indicator_count >= 1
    ):

        return "SUSPICIOUS"

    # -----------------------------------------------------
    # SAFE
    # -----------------------------------------------------

    return "SAFE"


# =========================================================
# MAIN EMAIL ANALYSIS
# =========================================================

def analyze_email(
    sender,
    subject,
    body
):

    sender = sender or ""
    subject = subject or ""
    body = body or ""

    # -----------------------------------------------------
    # COMBINE EMAIL CONTENT
    # -----------------------------------------------------

    full_text = (
        f"Sender: {sender}\n"
        f"Subject: {subject}\n"
        f"Body: {body}"
    )

    # -----------------------------------------------------
    # PARSE EMAIL
    # -----------------------------------------------------

    try:

        parsed_text = parse_email(
            sender,
            subject,
            body
        )

        if parsed_text:
            analysis_text = parsed_text
        else:
            analysis_text = full_text

    except Exception:

        analysis_text = full_text

    # -----------------------------------------------------
    # ML PREDICTION
    # -----------------------------------------------------

    try:

        ml_prediction_raw, ml_confidence = predict_email(
            analysis_text
        )

        # Convert numpy values to Python values
        try:
            ml_prediction = int(
                ml_prediction_raw
            )
        except Exception:
            ml_prediction = 0

        try:
            ml_confidence = float(
                ml_confidence
            )
        except Exception:
            ml_confidence = 0.0

    except Exception:

        ml_prediction = 0
        ml_confidence = 0.0

    # -----------------------------------------------------
    # SECURITY INDICATORS
    # -----------------------------------------------------

    indicators = find_indicators(
        analysis_text
    )

    # -----------------------------------------------------
    # URL EXTRACTION
    # -----------------------------------------------------

    urls = extract_urls(
        analysis_text
    )

    # -----------------------------------------------------
    # URL RISK
    # -----------------------------------------------------

    url_risk = calculate_url_risk(
        urls
    )

    # -----------------------------------------------------
    # CALCULATE RISK SCORE
    # -----------------------------------------------------

    risk_score = 0

    # ML contribution
    if ml_prediction == 1:

        risk_score += min(
            45,
            ml_confidence * 0.45
        )

    # Security indicators
    risk_score += min(
        30,
        len(indicators) * 8
    )

    # URL risk
    risk_score += min(
        25,
        url_risk * 0.25
    )

    # Urgent language
    text_lower = analysis_text.lower()

    urgent_words = [
        "urgent",
        "immediately",
        "action required",
        "act now",
        "final warning"
    ]

    urgent_count = sum(
        1
        for word in urgent_words
        if word in text_lower
    )

    risk_score += min(
        10,
        urgent_count * 3
    )

    # Limit score
    risk_score = min(
        100,
        round(risk_score)
    )

    # -----------------------------------------------------
    # FINAL PREDICTION
    # -----------------------------------------------------

    prediction = get_final_prediction(
        ml_prediction,
        ml_confidence,
        risk_score,
        indicators,
        url_risk
    )

    # -----------------------------------------------------
    # THREAT LEVEL
    # -----------------------------------------------------

    if prediction == "PHISHING":

        threat_level = "HIGH"

    elif prediction == "SUSPICIOUS":

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"

    # -----------------------------------------------------
    # WARNING MESSAGE
    # -----------------------------------------------------

    if prediction == "PHISHING":

        warning = (
            "⚠️ DON'T CLICK THIS MESSAGE. "
            "Do not enter your password, OTP or banking information."
        )

    elif prediction == "SUSPICIOUS":

        warning = (
            "⚠️ SUSPICIOUS EMAIL. "
            "Check the sender and links carefully before taking action."
        )

    else:

        warning = (
            "No major suspicious indicators detected."
        )

    # -----------------------------------------------------
    # ATTACK TYPE
    # -----------------------------------------------------

    if prediction == "PHISHING":

        if (
            "password" in analysis_text.lower()
            or "login" in analysis_text.lower()
        ):

            attack_type = "Credential Phishing"

        elif (
            "bank" in analysis_text.lower()
            or "credit card" in analysis_text.lower()
            or "otp" in analysis_text.lower()
        ):

            attack_type = "Financial Phishing"

        else:

            attack_type = "Phishing"

    elif prediction == "SUSPICIOUS":

        attack_type = "Potentially Suspicious"

    else:

        attack_type = "None"

    # -----------------------------------------------------
    # RETURN RESULT
    # -----------------------------------------------------

    return {

        "prediction": prediction,

        "risk_score": risk_score,

        "threat_level": threat_level,

        "confidence": round(
            ml_confidence,
            2
        ),

        "indicators": indicators,

        "urls": urls,

        "url_risk": url_risk,

        "attack_type": attack_type,

        "warning": warning
    }