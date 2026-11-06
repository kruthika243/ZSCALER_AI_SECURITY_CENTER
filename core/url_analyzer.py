
from urllib.parse import urlparse
import ipaddress
import re


def analyze_url(url: str) -> dict:
    """
    Parse and inspect a URL without visiting the website.
    """

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains invalid control characters.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname is missing.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name.")

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    return {
        "original_url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "url_length": len(url),
        "is_https": parsed.scheme.lower() == "https",
        "is_ip_address": is_ip,
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "has_at_symbol": "@" in url,
        "has_dash": "-" in hostname,
        "has_encoded_characters": bool(
            re.search(r"%[0-9a-fA-F]{2}", url)
        ),
        "special_character_count": sum(
            not char.isalnum() for char in url
        )
    }
