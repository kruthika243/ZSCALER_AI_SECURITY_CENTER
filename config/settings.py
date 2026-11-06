
APP_TITLE = "ZSCALER AI SECURITY CENTER"
APP_SUBTITLE = "Advanced Phishing Detection & Threat Intelligence"
APP_VERSION = "1.0.0"

TAGLINE = "TRUST NO ONE. VERIFY EVERY LINK."

RISK_LEVELS = {
    "LOW": (0, 24),
    "MODERATE": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}

DATABASE_PATH = "database/security_scans.db"

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "password",
    "signin",
    "confirm",
    "wallet",
    "suspended",
    "authenticate",
]
