# Zscaler AI Security Intelligence Center

A rule-based cybersecurity application for analyzing suspicious URLs and identifying potential phishing threats using structural URL analysis and Google Safe Browsing threat intelligence.

## Project Overview

The Zscaler AI Security Intelligence Center is an interactive Streamlit application designed to assess URL security risks. It combines structural URL analysis, explainable rule-based risk scoring, and Google Safe Browsing API integration to provide security insights.

## Key Features

- URL scanning and structural analysis
- Rule-based phishing risk assessment
- Google Safe Browsing API integration
- Threat intelligence results and threat categories
- Explainable risk indicators
- Interactive security analytics dashboard
- SQLite-based scan history
- PDF security report generation
- CSV export of scan results

## Technology Stack

- Python
- Streamlit
- Pandas
- SQLite
- Google Safe Browsing API
- Requests
- ReportLab

## Project Architecture

```text
ZSCALER_AI_SECURITY_CENTER/
├── app.py
├── assets/
├── config/
├── core/
├── database/
├── modules/
├── tests/
├── utils/
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/kruthika243/ZSCALER_AI_SECURITY_CENTER.git
cd ZSCALER_AI_SECURITY_CENTER
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Google Safe Browsing Configuration

Create:

`.streamlit/secrets.toml`

Add your Google Safe Browsing API key:

```toml
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_API_KEY"
```

Never commit your API key or secrets file to GitHub.

## Run the Application

```bash
streamlit run app.py
```

## Risk Assessment

The application combines structural URL indicators with Google Safe Browsing results.

Google Safe Browsing matches can identify known threats. A no-match response does not guarantee that a URL is safe.

The structural risk score is a rule-based assessment, not a machine-learning probability.

## Project Status

The application includes rule-based URL analysis, Google Safe Browsing integration, scan history, security analytics, and PDF reporting.

No machine-learning model training or ML performance evaluation is claimed in this version.

## Application Screenshots

### 1. Security Dashboard

The dashboard provides an overview of URL scans, security classifications, threat distribution, and recent scan activity.

![Security Dashboard](assets/screenshots/01-dashboard-top.png)

![Dashboard Activity](assets/screenshots/02-dashboard-bottom.png)

### 2. Live URL Scanner

The URL scanner combines structural URL analysis, explainable risk scoring, and Google Safe Browsing threat intelligence.

![URL Scanner](assets/screenshots/03-url-scanner-top.png)

![URL Analysis Results](assets/screenshots/04-url-scanner-bottom.png)

### 3. Threat Intelligence

This module analyzes stored URL indicators, suspicious keywords, domain characteristics, and risk distributions.

![Threat Intelligence Overview](assets/screenshots/05-threat-intelligence-top.png)

![Threat Indicator Analysis](assets/screenshots/06-threat-intelligence-bottom.png)

### 4. Security Scan History

Review saved URL scans, structural risk scores, Google Safe Browsing results, and overall security verdicts.

![Scan History](assets/screenshots/07-scan-history-top.png)

![Detailed Scan Information](assets/screenshots/08-scan-history-bottom.png)

### 5. PDF Security Report

The application generates downloadable PDF reports containing URL analysis, threat intelligence, detection evidence, and security recommendations.

![PDF Report Preview](assets/screenshots/09-security-report-preview.png)

![Generated PDF Security Report](assets/screenshots/10-security-report-pdf.png)

## Disclaimer

This application is an educational cybersecurity project. Its results should be treated as security indicators rather than a guarantee that a URL is safe or malicious.
