
import streamlit as st
import plotly.express as px
import pandas as pd

from database.scan_history import get_scan_counts, get_scan_history


def show_dashboard():

    st.markdown("""
    <div class="security-banner">
        <h2>🛡️ Security Intelligence Overview</h2>
        <p>Monitor phishing threats and URL security analysis.</p>
        <p>TRUST NO ONE. VERIFY EVERY LINK.</p>
    </div>
    """, unsafe_allow_html=True)

    # Retrieve actual database statistics
    counts = get_scan_counts()

    total = counts["TOTAL"]
    low = counts["LOW"]
    moderate = counts["MODERATE"]
    high = counts["HIGH"]
    critical = counts["CRITICAL"]

    suspicious = moderate + high + critical

    st.subheader("Security Overview")

    # KPI cards
    col1, col2, col3, col4 = st.columns(4)

    metrics = [
        (col1, "TOTAL SCANS", total),
        (col2, "SAFE / LOW RISK", low),
        (col3, "SUSPICIOUS URLS", suspicious),
        (col4, "HIGH / CRITICAL", high + critical),
    ]

    for col, label, value in metrics:

        with col:

            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.divider()

    left, right = st.columns(2)

    # Risk distribution
    with left:

        st.subheader("Threat Distribution")

        if total > 0:

            distribution = pd.DataFrame({
                "Risk Level": [
                    "Low",
                    "Moderate",
                    "High",
                    "Critical"
                ],
                "Scans": [
                    low,
                    moderate,
                    high,
                    critical
                ]
            })

            distribution = distribution[
                distribution["Scans"] > 0
            ]

            fig = px.pie(
                distribution,
                names="Risk Level",
                values="Scans",
                hole=0.60,
                title="URL Risk Classification"
            )

            fig.update_layout(
                paper_bgcolor="#080D18",
                plot_bgcolor="#080D18",
                font_color="#E5E7EB",
                legend_title_text="Risk Level"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info("No URL scans available yet.")

    # Security monitoring
    with right:

        st.subheader("Security Monitoring")

        if total > 0:

            st.metric(
                "Total Analyzed URLs",
                total
            )

            st.metric(
                "Moderate Risk",
                moderate
            )

            st.metric(
                "Critical Risk",
                critical
            )

            st.success(
                "Database connected. Scan statistics updated."
            )

        else:

            st.info(
                "No scan activity yet. "
                "Use the URL Scanner to begin."
            )

    st.divider()

    # Recent scan records
    st.subheader("Recent Security Scans")

    records = get_scan_history(limit=5)

    if records:

        recent_df = pd.DataFrame(records)

        display_columns = [
            "url",
            "risk_score",
            "risk_level",
            "scanned_at"
        ]

        st.dataframe(
            recent_df[display_columns],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info("No previous scan records found.")

    st.divider()

    st.subheader("Platform Status")

    st.success("Security dashboard operational.")

    st.caption(
        "Statistics are calculated from locally stored URL scan records. "
        "Risk classifications are based on heuristic indicators."
    )
