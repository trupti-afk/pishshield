# 🛡️ PhishShield AI — Cyber-Defense Phishing Detection Engine

[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Model](https://img.shields.io/badge/Algorithm-HistGradientBoosting%20%2B%20RandomForest-orange.svg)](https://scikit-learn.org/)
[![Accuracy](https://img.shields.io/badge/Accuracy-96.98%25%20(Domain%20Separated)-brightgreen.svg)]()
[![Interface](https://img.shields.io/badge/UI-Streamlit%20Web%20Dashboard%20%2B%20Terminal%20CLI-purple.svg)]()

> **PhishShield AI** is an advanced, user-friendly cybersecurity platform that detects and defends against malicious phishing URLs in real time. It blends **22 deep structural & information-theoretic features** with **domain-separated Machine Learning** and **heuristic threat intelligence** (brand impersonation, IP detection, high-abuse TLDs, and entropy anomalies).

---

## 🌟 Key Features

- **🌐 Cyberpunk Web Dashboard (Streamlit)**:
  - **Live URL Scanner**: Instant threat probability calculation, interactive visual gauge meter, and risk badges.
  - **URL Anatomy Decomposition**: Breaks down protocols, hostnames, registered domains, subdomains, and paths.
  - **Explainable AI (XAI)**: Identifies specific red flags (brand spoofing, high entropy, suspicious TLDs, excessive symbols).
  - **22-Feature Inspection Table**: Deep-dive table explaining each extracted metric with normal baseline comparisons.
  - **Batch Audit Suite**: Upload CSVs or paste multiple links, visualize safe vs phishing distributions, and export audited CSV reports.
- **💻 Interactive Cyber Terminal CLI**:
  - Full ASCII cyber banner with color-coded risk bars, ANSI tables, and interactive command loop (`scan`, `presets`, `audit`, `help`).
- **🛡️ Multi-Layer Threat Detection**:
  - **Machine Learning**: Pre-trained `HistGradientBoosting` classifier validated on unseen domains with **96.98% accuracy**.
  - **Rule-Based Threat Heuristics**: Detects raw IP hosts, Punycode/homograph attacks, brand impersonation (PayPal, Google, Netflix, Banks), and sensitive credential triggers.
- **🧠 Zero Data-Leakage Training**:
  - Uses `GroupShuffleSplit` on domains (`dom`) so training and testing sets share 0 domains, guaranteeing real-world performance.

---

## 🚀 Quick Start

### 1. Launch the Interactive Web Dashboard
```bash
streamlit run app.py
```
*(Or simply double-click `run_web.bat` on Windows!)*

### 2. Launch the Cyber Terminal Scanner
```bash
python cli.py
```
*(Or double-click `run_cli.bat` on Windows!)*

### 3. Scan a URL Directly via CLI
```bash
python cli.py "https://abacus-oo-niku-shiki.firebaseapp.com/"
```

### 4. Interactive Master Menu
```bash
python phishshield_ai.py
```
Provides an interactive menu to launch the web dashboard, CLI, quick URL scan, or self-tests.

---

## 📁 Project Architecture

```
pishshield/
├── core/
│   ├── __init__.py               # Package exports
│   ├── feature_extractor.py      # 22 numerical features & Shannon entropy
│   ├── threat_heuristics.py      # Brand spoofing, IP host & heuristic flags
│   └── classifier.py             # Model loader, risk calibration & scan engine
├── app.py                        # Streamlit Cyber-Defense Web App
├── cli.py                        # Interactive Terminal CLI with ASCII banner
├── train.py                      # Domain-separated training pipeline
├── phishshield_ai.py             # Modernized master entrypoint
├── phishshield_model_v1.pkl      # Pre-trained ML model package
├── Dataset.csv                   # Comprehensive URL feature dataset
├── requirements.txt              # Dependencies
├── run_web.bat                   # 1-click Windows Web App launcher
├── run_cli.bat                   # 1-click Windows CLI launcher
└── README.md                     # Documentation
```

---

## 📊 Extracted URL Features (22 Metrics)

| Feature | Category | Description |
| :--- | :--- | :--- |
| `entropy` | Information Theory | Shannon entropy (measures randomness and algorithmic token generation) |
| `url_len` | Structure | Total character length of the URL |
| `dom_len` | Structure | Length of the core registered domain name |
| `tld_len` | Structure | Length of the top-level domain suffix |
| `is_ip` | Network Host | Binary flag indicating if the host is a raw IPv4/IPv6 address |
| `subdom_cnt` | Subdomain | Number of stacked subdomains |
| `letter_cnt` / `letter_ratio` | Character Analysis | Count and ratio of alphabetic characters |
| `digit_cnt` / `digit_ratio` | Character Analysis | Count and ratio of numeric characters |
| `special_cnt` / `spec_ratio` | Character Analysis | Count and ratio of symbols (`/`, `.`, `-`, `_`, `=`, `?`, `&`) |
| `dot_cnt`, `dash_cnt`, `under_cnt` | Delimiters | Specific delimiter frequencies (often used in typosquatting) |
| `eq_cnt`, `qm_cnt`, `amp_cnt` | Query Parameters | Indicators of dynamic credential forms |
| `is_https` | Security Protocol | SSL/TLS certificate flag |
| `path_len`, `query_len`, `slash_cnt` | Routing | Structural path depth |

---

## 🧠 Retraining the Model

To retrain the classifier on your dataset using the domain-separated GroupShuffleSplit:

```bash
python train.py --data Dataset.csv --out phishshield_model_v1.pkl
```

Output includes:
- Confusion Matrix
- Precision, Recall, F1 Score
- Class distribution metrics
- Domain-isolation verification (0 shared domains between train/test)

---

## 🔒 Security Disclaimer
*Predictions generated by PhishShield AI are intended for security auditing, research, and assistive defense. Always cross-verify critical security decisions with certified endpoint protection and official browser warning systems.*
