
import json

import streamlit as st
import pandas as pd
import plotly.express as px

from database.scan_history import get_scan_history


def show_risk_analysis():

    st.title("📊 Advanced Risk Analysis")

    st.caption(
        "Understand URL risk scores, detection indicators "
        "and security recommendations."
    )

    records = get_scan_history(limit=5000)

    if not records:
        st.info(
            "No scan records available. "
            "Scan some URLs to begin risk analysis."
        )
        return

    df = pd.DataFrame(records)

    df["risk_score"] = pd.to_numeric(
        df["risk_score"], errors="coerce"
    ).fillna(0)

    # --------------------------------
    # 1. RISK SUMMARY
    # --------------------------------

    st.subheader("Risk Classification Summary")

    counts = df["risk_level"].value_counts()

    low = int(counts.get("LOW", 0))
    moderate = int(counts.get("MODERATE", 0))
    high = int(counts.get("HIGH", 0))
    critical = int(counts.get("CRITICAL", 0))

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Low Risk", low)
    c2.metric("Moderate Risk", moderate)
    c3.metric("High Risk", high)
    c4.metric("Critical Risk", critical)

    st.divider()

    # --------------------------------
    # 2. RISK DISTRIBUTION
    # --------------------------------

    st.subheader("Risk Distribution")

    risk_data = pd.DataFrame({
        "Risk Level": [
            "LOW",
            "MODERATE",
            "HIGH",
            "CRITICAL"
        ],
        "Scans": [
            low,
            moderate,
            high,
            critical
        ]
    })

    risk_data = risk_data[
        risk_data["Scans"] > 0
    ]

    left, right = st.columns(2)

    with left:

        fig = px.pie(
            risk_data,
            names="Risk Level",
            values="Scans",
            hole=0.60,
            title="Risk Classification"
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            font_color="#E5E7EB"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with right:

        fig = px.histogram(
            df,
            x="risk_score",
            nbins=10,
            title="URL Risk Score Distribution",
            labels={"risk_score": "Risk Score"}
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # --------------------------------
    # 3. DETECTION INDICATOR ANALYSIS
    # --------------------------------

    st.subheader("Detection Indicator Analysis")

    indicators = {
        "IP Address": 0,
        "Suspicious Keywords": 0,
        "URL Encoding": 0,
        "Excessive Subdomains": 0,
        "At Symbol": 0,
        "HTTP": 0
    }

    feature_records = []

    for record in records:

        try:
            features = json.loads(
                record.get("features") or "{}"
            )
        except (ValueError, TypeError):
            features = {}

        feature_records.append(features)

        indicators["IP Address"] += int(
            bool(features.get("is_ip_address", False))
        )

        indicators["Suspicious Keywords"] += int(
            features.get("suspicious_word_count", 0) > 0
        )

        indicators["URL Encoding"] += int(
            bool(features.get("has_encoded_characters", False))
        )

        indicators["Excessive Subdomains"] += int(
            features.get("subdomain_count", 0) >= 3
        )

        indicators["At Symbol"] += int(
            bool(features.get("has_at_symbol", False))
        )

        indicators["HTTP"] += int(
            not features.get("is_https", True)
        )

    indicator_df = pd.DataFrame(
        indicators.items(),
        columns=["Indicator", "Occurrences"]
    )

    fig = px.bar(
        indicator_df,
        x="Indicator",
        y="Occurrences",
        text="Occurrences",
        title="Frequency of Detected Indicators"
    )

    fig.update_layout(
        paper_bgcolor="#080D18",
        plot_bgcolor="#080D18",
        font_color="#E5E7EB"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.divider()

    # --------------------------------
    # 4. INDIVIDUAL URL RISK ASSESSMENT
    # --------------------------------

    st.subheader("Individual URL Risk Assessment")

    selected_id = st.selectbox(
        "Select a scanned URL",
        df["id"].tolist(),
        format_func=lambda value: (
            f"Scan #{value} — "
            f"{df.loc[df['id'] == value, 'hostname'].iloc[0]}"
        )
    )

    selected = df[df["id"] == selected_id].iloc[0]

    st.markdown("### Selected URL")

    st.code(selected["url"])

    score = int(selected["risk_score"])
    level = selected["risk_level"]

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Risk Score", f"{score}/100")

    with col2:
        st.metric("Risk Classification", level)

    if level == "LOW":
        st.success("LOW RISK")

    elif level == "MODERATE":
        st.warning("MODERATE RISK")

    else:
        st.error(level + " RISK")

    # Saved detection evidence
    try:
        reasons = json.loads(
            selected["reasons"] or "[]"
        )
    except (ValueError, TypeError):
        reasons = []

    st.markdown("### Detection Evidence")

    if reasons:

        for reason in reasons:
            st.markdown(f"- ⚠️ {reason}")

    else:

        st.info(
            "No configured suspicious URL indicators detected."
        )

    # Saved feature details
    try:
        selected_features = json.loads(
            selected["features"] or "{}"
        )
    except (ValueError, TypeError):
        selected_features = {}

    with st.expander("View extracted URL features"):

        st.json(selected_features)

    st.markdown("### Security Recommendation")

    if level in ["HIGH", "CRITICAL"]:

        st.error(
            "Avoid interacting with this URL. "
            "Verify the destination through an independent trusted channel."
        )

    elif level == "MODERATE":

        st.warning(
            "Exercise caution. Review the URL and verify "
            "the destination before entering sensitive information."
        )

    else:

        st.info(
            "No major configured indicators were detected. "
            "This does not guarantee that the website is safe."
        )

    st.caption(
        "Risk scores are generated by heuristic rules, "
        "not verified probabilities of malicious activity."
    )
