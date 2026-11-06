
import streamlit as st
import pandas as pd
import plotly.express as px
from collections import Counter

from database.scan_history import get_scan_history
from config.settings import SUSPICIOUS_KEYWORDS


def show_threat_intelligence():

    st.title("🛡️ Threat Intelligence Center")

    st.caption(
        "Analyze suspicious URL indicators and identify "
        "patterns across previously scanned URLs."
    )

    st.warning(
        "This module analyzes locally stored scan indicators. "
        "It does not connect to external threat feeds or verify "
        "whether a domain is malicious."
    )

    # Load actual scan history
    records = get_scan_history(limit=5000)

    if not records:

        st.info(
            "No scan records available. "
            "Analyze URLs using the Live URL Scanner first."
        )
        return

    df = pd.DataFrame(records)

    # Extract feature information from saved records
    features_list = []

    for record in records:

        try:
            import json

            features = json.loads(record.get("features") or "{}")
            features_list.append(features)

        except (ValueError, TypeError):
            features_list.append({})

    features_df = pd.DataFrame(features_list)

    # Indicator calculations
    total = len(records)

    ip_count = sum(
        bool(item.get("is_ip_address", False))
        for item in features_list
    )

    encoded_count = sum(
        bool(item.get("has_encoded_characters", False))
        for item in features_list
    )

    at_symbol_count = sum(
        bool(item.get("has_at_symbol", False))
        for item in features_list
    )

    suspicious_keyword_count = sum(
        int(item.get("suspicious_word_count", 0))
        for item in features_list
    )

    excessive_subdomains = sum(
        int(item.get("subdomain_count", 0)) >= 3
        for item in features_list
    )

    # Header
    st.divider()

    st.subheader("Threat Indicator Summary")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("URLs Analyzed", total)
    c2.metric("IP-Based URLs", ip_count)
    c3.metric("Encoded URLs", encoded_count)
    c4.metric("Keyword Matches", suspicious_keyword_count)

    st.divider()

    # Indicator distribution
    st.subheader("Suspicious Indicator Distribution")

    indicator_data = pd.DataFrame({
        "Indicator": [
            "IP Address",
            "URL Encoding",
            "@ Symbol",
            "Excessive Subdomains",
            "Suspicious Keywords"
        ],
        "Occurrences": [
            ip_count,
            encoded_count,
            at_symbol_count,
            excessive_subdomains,
            suspicious_keyword_count
        ]
    })

    left, right = st.columns(2)

    with left:

        fig = px.bar(
            indicator_data,
            x="Indicator",
            y="Occurrences",
            title="Detected URL Indicators",
            text="Occurrences"
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
            xaxis_title="Indicator",
            yaxis_title="Occurrences"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with right:

        risk_counts = (
            df["risk_level"]
            .value_counts()
            .reset_index()
        )

        risk_counts.columns = ["Risk Level", "Scans"]

        fig = px.pie(
            risk_counts,
            names="Risk Level",
            values="Scans",
            hole=0.60,
            title="Stored Scan Risk Distribution"
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            font_color="#E5E7EB"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # Suspicious keyword analysis
    st.subheader("Suspicious Keyword Intelligence")

    keyword_counter = Counter()

    for item in features_list:

        words = item.get("suspicious_words", [])

        if isinstance(words, list):
            keyword_counter.update(words)

    if keyword_counter:

        keyword_df = pd.DataFrame(
            keyword_counter.most_common(),
            columns=["Keyword", "Occurrences"]
        )

        st.dataframe(
            keyword_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info("No configured suspicious keywords were detected.")

    with st.expander("View configured detection keywords"):

        st.write(", ".join(SUSPICIOUS_KEYWORDS))

    st.divider()

    # Domain intelligence
    st.subheader("Domain Indicator Analysis")

    domain_data = []

    for record, features in zip(records, features_list):

        domain_data.append({
            "Hostname": record.get("hostname", ""),
            "IP Address": (
                "Yes"
                if features.get("is_ip_address")
                else "No"
            ),
            "Subdomains": features.get("subdomain_count", 0),
            "Risk Score": record.get("risk_score", 0),
            "Risk Level": record.get("risk_level", "UNKNOWN")
        })

    domain_df = pd.DataFrame(domain_data)

    if not domain_df.empty:

        st.dataframe(
            domain_df,
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    # Indicator details
    st.subheader("Threat Indicator Explanations")

    explanations = [
        (
            "IP-Based Hostname",
            "The URL hostname is an IP address instead of a domain name."
        ),
        (
            "URL Encoding",
            "The URL contains percent-encoded characters."
        ),
        (
            "Suspicious Keywords",
            "The URL contains configured words such as login, verify, "
            "banking, or password."
        ),
        (
            "Excessive Subdomains",
            "The hostname contains three or more subdomain labels."
        ),
        (
            "At Symbol",
            "The URL contains an @ character, which can be used "
            "in deceptive URL constructions."
        )
    ]

    for title, description in explanations:

        with st.expander(title):
            st.write(description)

    st.caption(
        "Indicator matches are heuristic signals, not proof of phishing. "
        "A URL without these indicators may still be malicious."
    )
