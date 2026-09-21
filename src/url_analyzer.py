import re
from urllib.parse import urlparse


# ==========================================
# EXTRACT URLs FROM EMAIL
# ==========================================

def extract_urls(text):

    if not text:
        return []

    pattern = r"https?://[^\s<>\"']+"

    urls = re.findall(
        pattern,
        text
    )

    # Remove duplicates
    urls = list(
        dict.fromkeys(urls)
    )

    return urls


# ==========================================
# ANALYZE SINGLE URL
# ==========================================

def analyze_url(url):

    if not url:

        return {
            "url": "",
            "risk_score": 0,
            "risk_level": "LOW",
            "indicators": []
        }


    indicators = []

    score = 0


    # --------------------------------------
    # Parse URL
    # --------------------------------------

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        path = parsed.path.lower()

    except Exception:

        return {
            "url": url,
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "indicators": [
                "Invalid URL format"
            ]
        }


    # Remove username/password if present

    hostname = parsed.hostname or ""

    hostname = hostname.lower()


    # ======================================
    # 1. HTTP instead of HTTPS
    # ======================================

    if parsed.scheme.lower() == "http":

        score += 15

        indicators.append(
            "URL does not use HTTPS"
        )


    # ======================================
    # 2. IP ADDRESS URL
    # ======================================

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(
        ip_pattern,
        hostname
    ):

        score += 30

        indicators.append(
            "URL uses an IP address instead of a domain"
        )


    # ======================================
    # 3. @ SYMBOL
    # ======================================

    if "@" in url:

        score += 25

        indicators.append(
            "Suspicious @ symbol in URL"
        )


    # ======================================
    # 4. VERY LONG URL
    # ======================================

    if len(url) > 120:

        score += 15

        indicators.append(
            "Unusually long URL"
        )


    # ======================================
    # 5. MANY SUBDOMAINS
    # ======================================

    subdomain_count = (
        hostname.count(".")
    )

    if subdomain_count >= 4:

        score += 15

        indicators.append(
            "Excessive subdomains"
        )


    # ======================================
    # 6. SUSPICIOUS WORDS
    # ======================================

    suspicious_words = [

        "login",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "password",
        "signin",
        "confirm",
        "update",
        "unlock",
        "suspended",
        "urgent",
        "authenticate",
        "wallet",
        "payment",
        "bank"

    ]


    found_words = []

    combined_url = (
        url.lower()
    )


    for word in suspicious_words:

        if word in combined_url:

            found_words.append(
                word
            )


    if found_words:

        score += min(
            30,
            len(found_words) * 8
        )

        indicators.append(
            "Suspicious keywords: "
            + ", ".join(found_words)
        )


    # ======================================
    # 7. URL SHORTENER
    # ======================================

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly",
        "cutt.ly",
        "shorturl.at"

    ]


    if hostname in shorteners:

        score += 25

        indicators.append(
            "URL shortening service detected"
        )


    # ======================================
    # 8. SUSPICIOUS FILE EXTENSIONS
    # ======================================

    dangerous_extensions = [

        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".msi",
        ".zip"

    ]


    for extension in dangerous_extensions:

        if path.endswith(
            extension
        ):

            score += 25

            indicators.append(
                "Suspicious file type in URL: "
                + extension
            )

            break


    # ======================================
    # 9. DOUBLE SLASH IN PATH
    # ======================================

    if "//" in path:

        score += 10

        indicators.append(
            "Unusual double slash in URL path"
        )


    # ======================================
    # LIMIT SCORE
    # ======================================

    score = min(
        score,
        100
    )


    # ======================================
    # RISK LEVEL
    # ======================================

    if score >= 70:

        risk_level = "HIGH"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    return {

        "url": url,

        "risk_score": score,

        "risk_level": risk_level,

        "indicators": indicators

    }


# ==========================================
# ANALYZE MULTIPLE URLs
# ==========================================

def analyze_urls(urls):

    if not urls:

        return {

            "urls": [],

            "max_risk_score": 0,

            "risk_level": "LOW",

            "indicators": []

        }


    results = []

    all_indicators = []

    max_score = 0


    for url in urls:

        result = analyze_url(
            url
        )

        results.append(
            result
        )

        all_indicators.extend(
            result["indicators"]
        )

        max_score = max(
            max_score,
            result["risk_score"]
        )


    # Remove duplicate indicators

    all_indicators = list(
        dict.fromkeys(
            all_indicators
        )
    )


    # Overall URL risk

    if max_score >= 70:

        risk_level = "HIGH"

    elif max_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    return {

        "urls": results,

        "max_risk_score": max_score,

        "risk_level": risk_level,

        "indicators": all_indicators

    }


# ==========================================
# QUICK URL RISK CHECK
# ==========================================

def get_url_risk(url):

    result = analyze_url(
        url
    )

    return (
        result["risk_score"],
        result["risk_level"]
    )