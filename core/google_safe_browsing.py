
import requests
import streamlit as st

from urllib.parse import urlparse


SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def check_google_safe_browsing(url: str) -> dict:

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "ERROR",
            "matches": [],
            "message": "Please provide a URL."
        }

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {
            "status": "ERROR",
            "matches": [],
            "message": "Enter a valid HTTP or HTTPS URL."
        }

    try:
        api_key = st.secrets["GOOGLE_SAFE_BROWSING_API_KEY"]
    except Exception:
        return {
            "status": "ERROR",
            "matches": [],
            "message": "Google API key is not configured."
        }

    payload = {
        "client": {
            "clientId": "zscaler_ai_security_center",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=(3, 6)
        )

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        if matches:
            return {
                "status": "MATCH",
                "matches": matches,
                "message": "Google Safe Browsing found a threat-list match."
            }

        return {
            "status": "NO_MATCH",
            "matches": [],
            "message": "No match found in the queried threat lists."
        }

    except requests.exceptions.Timeout:
        message = "Google Safe Browsing request timed out."

    except requests.exceptions.ConnectionError:
        message = "Could not connect to Google Safe Browsing."

    except requests.exceptions.HTTPError:
        message = f"Google API returned HTTP {response.status_code}."

    except requests.exceptions.RequestException as error:
        message = f"Google API request failed: {error}"

    return {
        "status": "ERROR",
        "matches": [],
        "message": message
    }
