
import streamlit as st
import plotly.graph_objects as go

from database.db import initialize_database
from database.scan_history import save_scan
from core.phishing_detector import scan_url
from core.google_safe_browsing import check_google_safe_browsing


def risk_gauge(score):

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": "Structural URL Risk Score"},
            number={"suffix": "/100"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#06B6D4"},
                "steps": [
                    {"range": [0, 25], "color": "#14532D"},
                    {"range": [25, 50], "color": "#854D0E"},
                    {"range": [50, 75], "color": "#9A3412"},
                    {"range": [75, 100], "color": "#7F1D1D"},
                ],
            },
        )
    )

    fig.update_layout(
        height=300,
        paper_bgcolor="#080D18",
        font_color="#E5E7EB",
        margin=dict(t=60, b=20, l=30, r=30),
    )

    return fig


def show_url_scanner():

    st.markdown("## 🔍 Live URL Security Scanner")

    st.write(
        "Analyze URLs using structural indicators, explainable risk scoring, "
        "and Google's live threat intelligence."
    )

    st.info(
        "The scanner analyzes URL structure and checks Google Safe Browsing. "
        "It does not visit or execute the submitted website."
    )

    url = st.text_input(
        "Enter URL to analyze",
        placeholder="https://example.com",
        key="scanner_url",
    )

    scan_button = st.button(
        "🔎 ANALYZE URL",
        width="stretch",
    )

    if scan_button:

        if not url.strip():
            st.error("Please enter a URL.")
            return

        try:
            initialize_database()

            # Show progress while analysis is running
            with st.spinner(
                "Analyzing URL structure and checking threat intelligence..."
            ):

                # 1. Perform structural URL analysis
                result = scan_url(url.strip())

                # 2. Normalize URL for Google Safe Browsing
                google_url = url.strip()

                if not google_url.startswith(("http://", "https://")):
                    google_url = "https://" + google_url

                # 3. Perform Google Safe Browsing check
                try:

                    google_result = check_google_safe_browsing(
                        google_url
                    )

                except Exception as error:

                    google_result = {
                        "status": "ERROR",
                        "matches": [],
                        "message": (
                            "Google Safe Browsing check failed: "
                            + type(error).__name__
                        ),
                    }

                # 4. Attach Google result
                result["google_safe_browsing"] = google_result

                # 5. Save scan history
                save_scan(result)

                # 6. Store latest result
                st.session_state["latest_scan"] = result

            st.success(
                "URL analysis completed and saved successfully."
            )

        except ValueError as error:
            st.error(str(error))
            return

        except Exception as error:
            st.error(
                f"URL analysis failed: {type(error).__name__}: {error}"
            )
            return

    # Retrieve latest scan
    result = st.session_state.get("latest_scan")

    if not result:
        st.info(
            "Enter a URL above to begin your security analysis."
        )
        return

    google_result = result.get("google_safe_browsing", {})
    google_status = google_result.get("status")

    st.divider()

    st.markdown("### Analysis Results")

    score_col, level_col = st.columns(2)

    # Structural risk score
    with score_col:

        st.plotly_chart(
            risk_gauge(result["risk_score"]),
            width="stretch",
        )

    # Overall security classification
    with level_col:

        st.markdown("#### Overall Security Classification")

        if google_status == "MATCH":

            st.error(
                "🚨 CRITICAL RISK — PHISHING THREAT DETECTED"
            )

        elif result["risk_level"] == "LOW":

            st.success("LOW RISK")

        elif result["risk_level"] == "MODERATE":

            st.warning("MODERATE RISK")

        elif result["risk_level"] == "HIGH":

            st.warning("HIGH RISK")

        else:

            st.error("CRITICAL RISK")

        st.write(
            "**Hostname:**",
            result["hostname"],
        )

        st.write(
            "**Structural risk score:**",
            f'{result["risk_score"]}/100',
        )

        if google_status == "MATCH":

            st.caption(
                "Overall classification elevated because Google "
                "Safe Browsing identified a threat."
            )

    # Google Safe Browsing intelligence
    st.divider()

    st.markdown("### 🌐 Live Google Threat Intelligence")

    if google_status == "MATCH":

        st.error(
            "⚠️ GOOGLE SAFE BROWSING: THREAT MATCH DETECTED"
        )

        st.write(google_result.get("message", ""))

        for match in google_result.get("matches", []):

            st.write(
                "**Threat type:**",
                match.get("threatType", "Not specified"),
            )

            st.write(
                "**Platform:**",
                match.get("platformType", "Not specified"),
            )

            st.write(
                "**Threat entry type:**",
                match.get("threatEntryType", "Not specified"),
            )

        st.warning(
            "Do not open or interact with this URL. "
            "Google Safe Browsing identified a threat."
        )

    elif google_status == "NO_MATCH":

        st.success(
            "✓ NO GOOGLE THREAT-LIST MATCH FOUND"
        )

        st.write(google_result.get("message", ""))

        st.caption(
            "No match does not guarantee that this website is safe."
        )

    elif google_status == "ERROR":

        st.warning(
            "Google Safe Browsing check was unavailable."
        )

        st.write(google_result.get("message", ""))

    else:

        st.info(
            "No Google Safe Browsing result is available."
        )

    # Detection evidence
    st.divider()

    st.markdown("### Detection Evidence")

    if result["reasons"]:

        for reason in result["reasons"]:
            st.markdown(f"- ⚠️ {reason}")

    else:

        st.success(
            "No configured suspicious URL indicators detected."
        )

    # Recommended action
    st.divider()

    st.markdown("### Recommended Action")

    if google_status == "MATCH":

        st.error(
            "BLOCK THIS URL. Google Safe Browsing identified a "
            "threat. Do not visit the website or enter personal "
            "information."
        )

    else:

        st.info(result["recommendation"])

    # Technical analysis
    with st.expander("View detailed technical analysis"):

        st.markdown("#### URL Structural Features")

        st.json(result["features"])

        st.markdown("#### Google Safe Browsing Response")

        st.json(google_result)

    st.caption(
        "The structural risk score is based on configured URL "
        "indicators, not a probability. A low score or Google "
        "NO_MATCH result does not guarantee that a website is legitimate."
    )
