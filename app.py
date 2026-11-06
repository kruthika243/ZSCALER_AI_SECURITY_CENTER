
import streamlit as st
from pathlib import Path

from config.settings import (
    APP_TITLE,
    APP_SUBTITLE,
    APP_VERSION
)

from database.db import initialize_database

from modules.dashboard import show_dashboard
from modules.url_scanner import show_url_scanner
from modules.threat_intelligence import show_threat_intelligence
from modules.risk_analysis import show_risk_analysis
from modules.security_analytics import show_security_analytics
from modules.scan_history import show_scan_history
from modules.security_reports import show_security_reports


st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize SQLite database
initialize_database()

# Load custom CSS if available
ROOT = Path(__file__).resolve().parent
CSS_PATH = ROOT / "assets" / "styles.css"

if CSS_PATH.exists():

    with open(CSS_PATH, "r", encoding="utf-8") as file:

        st.markdown(
            f"<style>{file.read()}</style>",
            unsafe_allow_html=True
        )

# Sidebar
with st.sidebar:

    st.markdown("# 🛡️ ZSCALER")
    st.caption("AI SECURITY CENTER")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Security Overview",
            "Live URL Scanner",
            "Threat Intelligence",
            "Risk Analysis",
            "Security Analytics",
            "Scan History",
            "Security Reports"
        ],
        key="main_navigation"
    )

    st.divider()
    st.caption(f"Version {APP_VERSION}")
    st.caption("Defensive Security Platform")

# Application header
st.markdown(f"# {APP_TITLE}")
st.caption(APP_SUBTITLE)

# Navigation
if page == "Security Overview":

    show_dashboard()

elif page == "Live URL Scanner":

    show_url_scanner()

elif page == "Threat Intelligence":

    show_threat_intelligence()

elif page == "Risk Analysis":

    show_risk_analysis()

elif page == "Security Analytics":

    show_security_analytics()

elif page == "Scan History":

    show_scan_history()

elif page == "Security Reports":

    show_security_reports()

# Footer
st.divider()

st.caption(
    "ZSCALER AI SECURITY CENTER | "
    "Trust No One. Verify Every Link."
)
