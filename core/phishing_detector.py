
from core.url_analyzer import analyze_url
from core.feature_extractor import extract_features
from core.risk_engine import calculate_risk
from core.explainability import generate_explanation


def scan_url(url: str) -> dict:
    """
    Complete URL analysis pipeline.
    """

    url_data = analyze_url(url)

    features = extract_features(url_data)

    risk = calculate_risk(features)

    explanation = generate_explanation(risk)

    return {
        "url": url_data["original_url"],
        "hostname": url_data["hostname"],
        "features": features,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "reasons": risk["reasons"],
        "recommendation": risk["recommendation"],
        "explanation": explanation
    }
