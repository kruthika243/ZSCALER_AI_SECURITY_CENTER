
import re
from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    """Check whether an HTTP or HTTPS URL has a valid hostname."""

    if not isinstance(url, str) or not url.strip():
        return False

    url = url.strip()

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return False

    # Reject explicitly supplied unsupported schemes.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        if not url.lower().startswith(("http://", "https://")):
            return False
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False

        return True

    except ValueError:
        return False
