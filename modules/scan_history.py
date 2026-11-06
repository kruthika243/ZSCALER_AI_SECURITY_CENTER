
import json
import streamlit as st
import pandas as pd

from database.scan_history import get_scan_history


def show_scan_history():

    st.markdown("## 📜 Security Scan History")

    st.write(
        "Review previously scanned URLs, structural risk scores, "
        "Google Safe Browsing results, and security classifications."
    )

    # Retrieve saved scans
    scans = get_scan_history(limit=200)

    if not scans:
        st.info("No scan history available. Scan a URL to get started.")
        return

    df = pd.DataFrame(scans)

    # Handle older records with missing Google fields
    for column, default in {
        "google_status": "NOT_CHECKED",
        "google_matches": "[]",
        "overall_verdict": None,
    }.items():
        if column not in df.columns:
            df[column] = default

    df["overall_verdict"] = df.apply(
        lambda row: (
            "CRITICAL"
            if row["google_status"] == "MATCH"
            else row["overall_verdict"]
            if pd.notna(row["overall_verdict"])
            else row["risk_level"]
        ),
        axis=1,
    )

    # Summary metrics
    total_scans = len(df)
    threats_detected = (df["google_status"] == "MATCH").sum()
    high_risk = df["overall_verdict"].isin(
        ["HIGH", "CRITICAL"]
    ).sum()
    google_checked = df["google_status"].isin(
        ["MATCH", "NO_MATCH"]
    ).sum()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Scans", total_scans)
    col2.metric("Google Threat Matches", int(threats_detected))
    col3.metric("High / Critical", int(high_risk))
    col4.metric("Google Checks Completed", int(google_checked))

    st.divider()

    # Filters
    st.markdown("### Filter Scan Records")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        verdict_options = ["ALL"] + sorted(
            df["overall_verdict"].dropna().unique().tolist()
        )

        selected_verdict = st.selectbox(
            "Overall Security Verdict",
            verdict_options,
        )

    with filter_col2:
        google_options = ["ALL"] + sorted(
            df["google_status"].fillna("NOT_CHECKED").unique().tolist()
        )

        selected_google = st.selectbox(
            "Google Safe Browsing Status",
            google_options,
        )

    filtered_df = df.copy()

    if selected_verdict != "ALL":
        filtered_df = filtered_df[
            filtered_df["overall_verdict"] == selected_verdict
        ]

    if selected_google != "ALL":
        filtered_df = filtered_df[
            filtered_df["google_status"].fillna("NOT_CHECKED")
            == selected_google
        ]

    st.divider()

    st.markdown("### Saved Scan Records")

    if filtered_df.empty:
        st.info("No records match the selected filters.")
        return

    # Display table
    display_columns = [
        "id",
        "url",
        "hostname",
        "risk_score",
        "risk_level",
        "google_status",
        "overall_verdict",
        "scanned_at",
    ]

    display_df = filtered_df[display_columns].copy()

    display_df.columns = [
        "Scan ID",
        "URL",
        "Hostname",
        "Structural Score",
        "Structural Risk",
        "Google Status",
        "Overall Verdict",
        "Scanned At",
    ]

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # Individual scan details
    st.markdown("### Detailed Scan Information")

    scan_ids = filtered_df["id"].tolist()

    selected_scan_id = st.selectbox(
        "Select Scan ID",
        scan_ids,
        format_func=lambda scan_id: (
            f"Scan #{scan_id} — "
            f"{filtered_df.loc[filtered_df['id'] == scan_id, 'hostname'].iloc[0]}"
        ),
    )

    selected_scan = filtered_df[
        filtered_df["id"] == selected_scan_id
    ].iloc[0]

    st.markdown("#### URL Information")

    st.write("**URL:**", selected_scan["url"])
    st.write("**Hostname:**", selected_scan["hostname"])
    st.write("**Scan timestamp:**", selected_scan["scanned_at"])

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:
        st.metric(
            "Structural Risk Score",
            f"{selected_scan['risk_score']}/100",
        )

        st.write(
            "**Structural classification:**",
            selected_scan["risk_level"],
        )

    with detail_col2:
        verdict = selected_scan["overall_verdict"]

        if verdict == "CRITICAL":
            st.error("🚨 CRITICAL RISK")
        elif verdict == "HIGH":
            st.warning("HIGH RISK")
        elif verdict == "MODERATE":
            st.warning("MODERATE RISK")
        else:
            st.success("LOW RISK")

        st.write(
            "**Google status:**",
            selected_scan["google_status"],
        )

    st.divider()

    # Google Safe Browsing details
    st.markdown("### 🌐 Google Safe Browsing Intelligence")

    google_status = selected_scan["google_status"]

    if google_status == "MATCH":

        st.error("THREAT MATCH DETECTED")

        try:
            matches = json.loads(selected_scan["google_matches"] or "[]")
        except (TypeError, json.JSONDecodeError):
            matches = []

        if matches:
            for index, match in enumerate(matches, start=1):

                st.markdown(f"**Threat Match {index}**")

                st.write(
                    "**Threat Type:**",
                    match.get("threatType", "Not specified"),
                )

                st.write(
                    "**Platform:**",
                    match.get("platformType", "Not specified"),
                )

                st.write(
                    "**Entry Type:**",
                    match.get("threatEntryType", "Not specified"),
                )

        else:
            st.write("Google reported a match, but no match details were saved.")

        st.warning(
            "Recommended action: Block this URL and avoid visiting it."
        )

    elif google_status == "NO_MATCH":

        st.success("NO GOOGLE THREAT-LIST MATCH FOUND")

        st.caption(
            "This does not guarantee that the website is safe."
        )

    elif google_status == "ERROR":

        st.warning("Google Safe Browsing check failed or was unavailable.")

    else:

        st.info("Google Safe Browsing was not checked for this record.")

    st.divider()

    # Detection evidence
    st.markdown("### Detection Evidence")

    try:
        reasons = json.loads(selected_scan["reasons"] or "[]")
    except (TypeError, json.JSONDecodeError):
        reasons = []

    if reasons:
        for reason in reasons:
            st.markdown(f"- ⚠️ {reason}")
    else:
        st.success("No configured structural indicators detected.")

    # Recommendation
    st.markdown("### Recommended Action")

    if google_status == "MATCH":
        st.error(
            "BLOCK THIS URL. Google Safe Browsing identified a threat."
        )
    else:
        st.info(selected_scan["recommendation"])

    # Technical information
    with st.expander("View Technical Features"):

        try:
            features = json.loads(selected_scan["features"] or "{}")
        except (TypeError, json.JSONDecodeError):
            features = {}

        st.json(features)

    # Export filtered history
    st.divider()

    st.markdown("### Export Scan History")

    csv_data = display_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📥 Download Scan History CSV",
        data=csv_data,
        file_name="zscaler_scan_history.csv",
        mime="text/csv",
        use_container_width=True,
    )
