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

## Disclaimer

This application is an educational cybersecurity project. Its results should be treated as security indicators rather than a guarantee that a URL is safe or malicious.
