
from core.risk_engine import calculate_risk


def test_ip_address_increases_risk():
    features = {
        "is_ip_address": True,
        "suspicious_word_count": 0,
        "suspicious_words": [],
        "has_encoded_characters": False,
        "subdomain_count": 0,
        "url_length": 30,
        "is_https": True,
        "has_at_symbol": False,
        "special_character_count": 5
    }

    result = calculate_risk(features)

    assert result["risk_score"] >= 25
    assert result["risk_level"] == "MODERATE"


def test_clean_url_has_low_risk():
    features = {
        "is_ip_address": False,
        "suspicious_word_count": 0,
        "suspicious_words": [],
        "has_encoded_characters": False,
        "subdomain_count": 0,
        "url_length": 25,
        "is_https": True,
        "has_at_symbol": False,
        "special_character_count": 5
    }

    result = calculate_risk(features)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
