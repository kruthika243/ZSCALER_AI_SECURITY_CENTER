
def generate_explanation(result: dict) -> str:

    score = result["risk_score"]
    level = result["risk_level"]
    reasons = result["reasons"]

    explanation = [
        f"Risk classification: {level}",
        f"Risk score: {score}/100"
    ]

    if reasons:
        explanation.append("Detection evidence:")

        for reason in reasons:
            explanation.append(f"- {reason}")
    else:
        explanation.append(
            "No configured suspicious URL indicators detected."
        )

    explanation.append(result["recommendation"])

    return "\n".join(explanation)
