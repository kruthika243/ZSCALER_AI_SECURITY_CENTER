
from config.settings import SUSPICIOUS_KEYWORDS


def extract_features(url_data: dict) -> dict:

    url = url_data["original_url"].lower()
    hostname = url_data["hostname"].lower()

    suspicious_words = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in url
    ]

    return {
        "url_length": url_data["url_length"],
        "is_https": url_data["is_https"],
        "is_ip_address": url_data["is_ip_address"],
        "subdomain_count": url_data["subdomain_count"],
        "has_at_symbol": url_data["has_at_symbol"],
        "has_dash": url_data["has_dash"],
        "has_encoded_characters": url_data[
            "has_encoded_characters"
        ],
        "special_character_count": url_data[
            "special_character_count"
        ],
        "suspicious_words": suspicious_words,
        "suspicious_word_count": len(suspicious_words),
        "hostname": hostname
    }
