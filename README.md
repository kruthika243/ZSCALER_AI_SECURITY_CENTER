# Zscaler AI Security Intelligence Center

A data-science and cybersecurity project for phishing URL classification.

## Primary dataset
UCI PhiUSIIL Phishing URL (Website) Dataset, UCI Machine Learning Repository, dataset ID 967:
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

The original dataset contains URL and webpage-derived attributes. The deployed URL-only model must use only features that can be computed from the submitted URL. Do not use webpage-derived attributes in that model.

## Setup (macOS)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Download and validate
```bash
python src/download_dataset.py
python src/validate_dataset.py
```

The download step writes `data/raw/phiusiil.csv`. The validation step creates:
- `reports/dataset_validation_report.json`
- `reports/class_distribution.csv`

## Research safeguards
- Verify label mapping from the UCI dataset documentation.
- Inspect exact columns before selecting features.
- Remove duplicate records and investigate duplicate URLs with conflicting labels.
- Avoid target leakage.
- Fit preprocessing only on training data.
- Use stratified train/validation/test partitions.
- Report precision, recall, F1, ROC-AUC, PR-AUC and confusion matrix.
- Do not treat a low-risk prediction as proof that a URL is safe.

## Project status
Dataset selected; download and initial validation scripts prepared. No model has been trained and no performance results are claimed yet.
