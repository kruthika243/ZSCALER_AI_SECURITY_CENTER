
import json

import streamlit as st
import pandas as pd
import plotly.express as px

from database.scan_history import get_scan_history


def show_security_analytics():

    st.title("📈 Security Analytics Center")

    st.caption(
        "Explore URL scanning activity, structural risk patterns, "
        "Google Safe Browsing intelligence, and security trends."
    )

    records = get_scan_history(limit=5000)

    if not records:
        st.info("No scan data available yet. Scan URLs first.")
        return

    df = pd.DataFrame(records)

    # --------------------------------
    # 1. PREPARE DATA
    # --------------------------------

    required_defaults = {
        "google_status": "NOT_CHECKED",
        "google_matches": "[]",
        "overall_verdict": None,
    }

    for column, default in required_defaults.items():
        if column not in df.columns:
            df[column] = default

    df["risk_score"] = pd.to_numeric(
        df["risk_score"], errors="coerce"
    ).fillna(0)

    df["scanned_at"] = pd.to_datetime(
        df["scanned_at"], errors="coerce", utc=True
    )

    df = df.dropna(subset=["scanned_at"]).copy()

    if df.empty:
        st.warning("No valid scan timestamps are available.")
        return

    df["google_status"] = (
        df["google_status"]
        .fillna("NOT_CHECKED")
        .replace("", "NOT_CHECKED")
    )

    # Derive overall verdict for older records
    def determine_verdict(row):

        if row["google_status"] == "MATCH":
            return "CRITICAL"

        existing = row["overall_verdict"]

        if pd.notna(existing) and str(existing).strip():
            return str(existing).upper()

        return str(row["risk_level"]).upper()

    df["overall_verdict"] = df.apply(
        determine_verdict,
        axis=1
    )

    total = len(df)

    # Google statistics
    google_matches = int(
        (df["google_status"] == "MATCH").sum()
    )

    google_no_match = int(
        (df["google_status"] == "NO_MATCH").sum()
    )

    google_errors = int(
        (df["google_status"] == "ERROR").sum()
    )

    google_checked = google_matches + google_no_match

    google_not_checked = int(
        (df["google_status"] == "NOT_CHECKED").sum()
    )

    detection_rate = (
        (google_matches / google_checked) * 100
        if google_checked > 0
        else 0
    )

    average_score = df["risk_score"].mean()

    high_risk = int(
        df["overall_verdict"].isin(
            ["HIGH", "CRITICAL"]
        ).sum()
    )

    unique_domains = df["hostname"].nunique()

    # --------------------------------
    # 2. ANALYTICS OVERVIEW
    # --------------------------------

    st.subheader("Analytics Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total Scans",
        total
    )

    c2.metric(
        "Average Risk Score",
        f"{average_score:.1f}/100"
    )

    c3.metric(
        "High / Critical Scans",
        high_risk
    )

    c4.metric(
        "Unique Hostnames",
        unique_domains
    )

    st.divider()

    # --------------------------------
    # 3. GOOGLE SAFE BROWSING ANALYTICS
    # --------------------------------

    st.subheader("🌐 Google Safe Browsing Intelligence")

    g1, g2, g3, g4 = st.columns(4)

    g1.metric(
        "Threat Matches",
        google_matches
    )

    g2.metric(
        "No Threat Match",
        google_no_match
    )

    g3.metric(
        "Completed Checks",
        google_checked
    )

    g4.metric(
        "Detection Rate",
        f"{detection_rate:.1f}%"
    )

    st.caption(
        "Detection rate = Google threat matches divided by completed "
        "Google checks. API errors and unchecked scans are excluded."
    )

    google_left, google_right = st.columns(2)

    with google_left:

        google_status_df = pd.DataFrame({
            "Google Status": [
                "MATCH",
                "NO_MATCH",
                "ERROR",
                "NOT_CHECKED",
            ],
            "Scans": [
                google_matches,
                google_no_match,
                google_errors,
                google_not_checked,
            ],
        })

        fig = px.pie(
            google_status_df,
            names="Google Status",
            values="Scans",
            title="Google Safe Browsing Status Distribution",
            hole=0.45,
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with google_right:

        verdict_counts = (
            df["overall_verdict"]
            .value_counts()
            .reindex(
                ["LOW", "MODERATE", "HIGH", "CRITICAL"],
                fill_value=0
            )
            .reset_index()
        )

        verdict_counts.columns = [
            "Overall Verdict",
            "Number of Scans",
        ]

        fig = px.bar(
            verdict_counts,
            x="Overall Verdict",
            y="Number of Scans",
            text="Number of Scans",
            title="Overall Security Verdict Distribution",
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # --------------------------------
    # 4. GOOGLE THREAT CATEGORIES
    # --------------------------------

    st.divider()

    st.subheader("Google Threat Category Analysis")

    threat_categories = []

    for _, record in df.iterrows():

        if record["google_status"] != "MATCH":
            continue

        try:
            matches = json.loads(
                record.get("google_matches") or "[]"
            )

            if not isinstance(matches, list):
                continue

            for match in matches:

                if isinstance(match, dict):

                    category = match.get(
                        "threatType",
                        "UNKNOWN"
                    )

                    threat_categories.append(category)

        except (ValueError, TypeError):
            continue

    if threat_categories:

        threat_df = pd.DataFrame({
            "Threat Category": threat_categories
        })

        category_counts = (
            threat_df["Threat Category"]
            .value_counts()
            .reset_index()
        )

        category_counts.columns = [
            "Threat Category",
            "Matches",
        ]

        fig = px.bar(
            category_counts,
            x="Threat Category",
            y="Matches",
            text="Matches",
            title="Google Detected Threat Categories",
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.info(
            "No Google threat categories are available in the saved scans."
        )

    st.divider()

    # --------------------------------
    # 5. SCAN ACTIVITY OVER TIME
    # --------------------------------

    st.subheader("URL Scanning Activity")

    df["scan_date"] = (
        df["scanned_at"]
        .dt.tz_convert(None)
        .dt.date
    )

    daily_scans = (
        df.groupby("scan_date")
        .size()
        .reset_index(name="Total Scans")
    )

    fig = px.line(
        daily_scans,
        x="scan_date",
        y="Total Scans",
        markers=True,
        title="Daily URL Scanning Activity",
    )

    fig.update_layout(
        paper_bgcolor="#080D18",
        plot_bgcolor="#080D18",
        font_color="#E5E7EB",
        xaxis_title="Date",
        yaxis_title="Number of Scans",
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.divider()

    # --------------------------------
    # 6. STRUCTURAL RISK ANALYSIS
    # --------------------------------

    st.subheader("Structural Risk Analysis")

    left, right = st.columns(2)

    with left:

        risk_counts = (
            df["risk_level"]
            .value_counts()
            .reindex(
                ["LOW", "MODERATE", "HIGH", "CRITICAL"],
                fill_value=0
            )
            .reset_index()
        )

        risk_counts.columns = [
            "Risk Level",
            "Number of Scans",
        ]

        fig = px.bar(
            risk_counts,
            x="Risk Level",
            y="Number of Scans",
            text="Number of Scans",
            title="Scans by Structural Risk Level",
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
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
            title="Structural Risk Score Distribution",
        )

        fig.update_layout(
            paper_bgcolor="#080D18",
            plot_bgcolor="#080D18",
            font_color="#E5E7EB",
            xaxis_title="Structural Risk Score",
            yaxis_title="Number of URLs",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # --------------------------------
    # 7. SECURITY INDICATOR FREQUENCY
    # --------------------------------

    st.subheader("Security Indicator Frequency")

    indicator_counts = {
        "IP Address": 0,
        "Suspicious Keywords": 0,
        "URL Encoding": 0,
        "Excessive Subdomains": 0,
        "At Symbol": 0,
        "HTTP": 0,
    }

    for record in records:

        try:
            features = json.loads(
                record.get("features") or "{}"
            )

            if not isinstance(features, dict):
                features = {}

        except (ValueError, TypeError):
            features = {}

        indicator_counts["IP Address"] += int(
            bool(features.get("is_ip_address", False))
        )

        indicator_counts["Suspicious Keywords"] += int(
            features.get("suspicious_word_count", 0) > 0
        )

        indicator_counts["URL Encoding"] += int(
            bool(features.get("has_encoded_characters", False))
        )

        indicator_counts["Excessive Subdomains"] += int(
            features.get("subdomain_count", 0) >= 3
        )

        indicator_counts["At Symbol"] += int(
            bool(features.get("has_at_symbol", False))
        )

        indicator_counts["HTTP"] += int(
            not features.get("is_https", True)
        )

    indicator_df = pd.DataFrame(
        indicator_counts.items(),
        columns=["Indicator", "Occurrences"],
    )

    fig = px.bar(
        indicator_df,
        x="Indicator",
        y="Occurrences",
        text="Occurrences",
        title="Detected Structural Security Indicators",
    )

    fig.update_layout(
        paper_bgcolor="#080D18",
        plot_bgcolor="#080D18",
        font_color="#E5E7EB",
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.divider()

    # --------------------------------
    # 8. HOSTNAME ANALYSIS
    # --------------------------------

    st.subheader("Hostname Analysis")

    hostname_stats = (
        df.groupby("hostname")
        .agg(
            Total_Scans=("id", "count"),
            Average_Risk=("risk_score", "mean"),
            Maximum_Risk=("risk_score", "max"),
            Google_Threat_Matches=(
                "google_status",
                lambda values: (values == "MATCH").sum()
            ),
        )
        .reset_index()
    )

    hostname_stats["Average_Risk"] = (
        hostname_stats["Average_Risk"].round(1)
    )

    hostname_stats = hostname_stats.sort_values(
        ["Google_Threat_Matches", "Maximum_Risk"],
        ascending=False,
    )

    st.dataframe(
        hostname_stats,
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # --------------------------------
    # 9. RECENT ANALYTICS RECORDS
    # --------------------------------

    st.subheader("Recent Analytics Records")

    recent = df.sort_values(
        "scanned_at",
        ascending=False
    ).head(10)

    recent_columns = [
        "url",
        "risk_score",
        "risk_level",
        "google_status",
        "overall_verdict",
        "scanned_at",
    ]

    st.dataframe(
        recent[recent_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # --------------------------------
    # 10. EXPORT ANALYTICS
    # --------------------------------

    st.subheader("Export Security Analytics")

    export_columns = [
        "id",
        "url",
        "hostname",
        "risk_score",
        "risk_level",
        "google_status",
        "overall_verdict",
        "scanned_at",
    ]

    export_df = df[export_columns].copy()

    csv_data = export_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download Security Analytics CSV",
        data=csv_data,
        file_name="zscaler_security_analytics.csv",
        mime="text/csv",
        use_container_width=True,
    )

    st.caption(
        "Analytics are calculated from locally stored scan records. "
        "Repeated scans are counted separately. Google threat matches "
        "represent provider-reported threat-list matches, while "
        "structural risk scores represent configured URL indicators. "
        "A NO_MATCH result does not guarantee website safety."
    )
