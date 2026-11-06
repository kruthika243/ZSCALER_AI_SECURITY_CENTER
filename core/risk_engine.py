
def calculate_risk(features: dict) -> dict:

    score = 0
    reasons = []

    if features["is_ip_address"]:
        score += 25
        reasons.append("Hostname uses an IP address.")

    if features["suspicious_word_count"] > 0:
        score += min(
            15 * features["suspicious_word_count"], 30
        )
        reasons.append(
            "Suspicious keywords: "
            + ", ".join(features["suspicious_words"])
        )

    if features["has_encoded_characters"]:
        score += 20
        reasons.append("URL contains encoded characters.")

    if features["subdomain_count"] >= 3:
        score += 10
        reasons.append("Excessive number of subdomains.")

    if features["url_length"] > 100:
        score += 10
        reasons.append("Unusually long URL.")

    if not features["is_https"]:
        score += 5
        reasons.append("URL does not use HTTPS.")

    if features["has_at_symbol"]:
        score += 10
        reasons.append("URL contains an @ symbol.")

    if features["special_character_count"] > 15:
        score += 10
        reasons.append("High number of special characters.")

    score = min(score, 100)

    if score < 25:
        level = "LOW"
    elif score < 50:
        level = "MODERATE"
    elif score < 75:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "recommendation": (
            "Exercise caution and verify the destination."
            if score >= 25
            else "No major URL indicators detected. "
                 "This does not guarantee the website is safe."
        )
    }
