
import json
import streamlit as st

from database.scan_history import get_scan_history
from modules.report_generator import generate_security_report


def show_security_reports():

    st.title("📄 Security Reports")

    st.caption(
        "Generate downloadable PDF reports containing URL analysis, "
        "structural risk scoring, and Google Safe Browsing intelligence."
    )

    records = get_scan_history(limit=5000)

    if not records:
        st.info(
            "No scan records available. "
            "Scan a URL before generating a report."
        )
        return

    st.subheader("Select a Scan")

    selected_id = st.selectbox(
        "Choose a scan record",
        [record["id"] for record in records],
        format_func=lambda scan_id: next(
            (
                f"Scan #{record['id']} | "
                f"{record['hostname']} | "
                f"{record.get('overall_verdict') or record['risk_level']} | "
                f"{record['risk_score']}/100"
                for record in records
                if record["id"] == scan_id
            ),
            str(scan_id)
        )
    )

    selected = next(
        record for record in records
        if record["id"] == selected_id
    )

    # Handle older scan records
    google_status = selected.get("google_status") or "NOT_CHECKED"

    try:
        google_matches = json.loads(
            selected.get("google_matches") or "[]"
        )
    except (ValueError, TypeError):
        google_matches = []

    overall_verdict = (
        "CRITICAL"
        if google_status == "MATCH"
        else selected.get("overall_verdict") or selected["risk_level"]
    )

    st.divider()

    # Report preview
    st.subheader("Report Preview")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Structural Risk Score",
        f"{selected['risk_score']}/100"
    )

    col2.metric(
        "Overall Verdict",
        overall_verdict
    )

    col3.metric(
        "Scan ID",
        selected["id"]
    )

    st.write("**URL:**", selected["url"])
    st.write("**Hostname:**", selected["hostname"])
    st.write("**Scan Timestamp:**", selected["scanned_at"])

    st.divider()

    # Google Safe Browsing preview
    st.subheader("🌐 Google Safe Browsing Intelligence")

    if google_status == "MATCH":

        st.error("🚨 THREAT MATCH DETECTED")

        for index, match in enumerate(google_matches, start=1):

            st.markdown(f"**Threat Match {index}**")

            st.write(
                "**Threat Type:**",
                match.get("threatType", "Not specified")
            )

            st.write(
                "**Platform:**",
                match.get("platformType", "Not specified")
            )

            st.write(
                "**Entry Type:**",
                match.get("threatEntryType", "Not specified")
            )

        st.warning(
            "Recommended action: Block this URL and avoid visiting it."
        )

    elif google_status == "NO_MATCH":

        st.success("NO GOOGLE THREAT-LIST MATCH FOUND")

        st.caption(
            "A no-match result does not guarantee that a website is safe."
        )

    elif google_status == "ERROR":

        st.warning("Google Safe Browsing check was unavailable.")

    else:

        st.info(
            "Google Safe Browsing was not checked for this historical scan."
        )

    st.divider()

    st.subheader("Generate PDF Report")

    st.write(
        "The PDF report includes the selected scan's analysis "
        "and available Google threat-intelligence information."
    )

    try:

        pdf_bytes = generate_security_report(selected_id)

        st.download_button(
            label="📥 Download Security Report (PDF)",
            data=pdf_bytes,
            file_name=f"Zscaler_Security_Report_{selected_id}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

        st.success("Your PDF report is ready.")

    except Exception as error:

        st.error(f"Unable to generate report: {error}")
