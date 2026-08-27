# Secure Sight – AI-Powered Phishing & Cyber Threat Detection System

> **Secure Sight** is an enterprise-grade, multi-vector AI security analysis platform that detects phishing URLs, fraudulent email content, and AI-generated/deepfake images — with explainable, real-time results.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.2.5-lightgrey.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4.2-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](#license--attribution)

---

## 🌟 Key Features & Core Capabilities

### 1️⃣ URL Phishing Detection & Threat Scoring
* **Structural & Lexical Feature Extraction:** Extracts 11+ numeric indicators per URL (e.g., Shannon Entropy, host/path lengths, special symbol frequencies, protocol flags, and suspicious keywords).
* **Soft-Voting Ensemble Model:** Combines **Random Forest** (300 trees), **Logistic Regression** (L2 regularized), and **Decision Tree** classifiers trained on 233,000+ URL samples.
* **Domain Reputation Intelligence:** Real-time domain age calculation via WHOIS lookups, SSL certificate validation, and dynamic local blacklist matching.
* **Explainable AI (XAI) Output:** Generates clear, human-readable explanations detailing why a specific URL was classified as phishing or legitimate.

### 2️⃣ Email Phishing Content Analysis
* **NLP & Keyword Signal Extraction:** Analyzes email bodies for urgency signals, financial/bank keyword triggers, action requests, and embedded hyper-links.
* **Dedicated Email Classification Model:** A dedicated ML model predicting email phishing probability with high recall.

### 3️⃣ Deepfake & AI-Generated Image Forensics
* **Multi-Signal Vision Analysis:** Inspects uploaded image files (≤ 5 MB; PNG, JPG, JPEG, WEBP) using digital forensic techniques.
* **Artifact Detection Metrics:** Evaluates **Error Level Analysis (ELA)**, **Fast Fourier Transform (FFT)** frequency artifacts, noise variance analysis, and visual anomaly signals to flag synthetic/manipulated media.

### 4️⃣ RESTful Security API
* **Programmatic Integration:** The `/api/analyze` endpoint accepts JSON payloads for automated URL scanning within external security tools or CI/CD pipelines.

### 5️⃣ Enterprise Security & Deployment Ready
* **Built-in Security Headers:** Content Security Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and non-root container execution.
* **Containerized Architecture:** Production-ready multi-stage Docker build served via Gunicorn.

---

## 📊 Model Performance Metrics

Trained on **233,670** URL samples with **SMOTE** class balancing:

| Metric | Score |
| :--- | :--- |
| **Accuracy** | **99.73%** |
| **Precision** | **99.59%** |
| **Recall** | **99.94%** |
| **F1 Score** | **99.76%** |
| **ROC-AUC** | **99.86%** |

---

## 📂 Project Architecture

```
capstone Project/
├── app/                        # Flask Web Application
│   ├── app.py                  # Server entry point & configuration
│   ├── routes.py               # Web UI routes & REST API endpoints
│   ├── templates/              # HTML UI templates
│   └── static/                 # CSS, JavaScript & visual assets
├── utils/                      # Core Security & ML Engine
│   ├── feature_extraction.py   # Lexical & structural URL feature extraction
│   ├── email_extraction.py     # Email text feature extraction
│   ├── image_analysis.py       # ELA, FFT & image noise forensic engine
│   ├── reputation.py           # WHOIS, SSL, and risk scoring module
│   └── model.py                # Ensemble & email model loaders
├── scripts/                    # Automation & Data Pipeline
│   ├── run_pipeline.py         # End-to-end master pipeline runner
│   ├── preprocess.py           # URL dataset preprocessing
│   ├── feature_engineering.py  # Feature engineering to Parquet format
│   ├── preprocess_emails.py    # Email dataset preprocessing
│   ├── generate_blacklist.py   # Local blacklist compiler
│   ├── train_ensemble.py       # URL ensemble model trainer
│   └── train_email_model.py    # Email model trainer
├── models/                     # Serialized Model Artifacts (.pkl, metadata.json)
├── data/                       # Datasets & Blacklists
├── tests/                      # Pytest Automated Test Suite
│   ├── test_routes.py          # Route & endpoint unit/integration tests
│   └── test_utils.py           # Feature extraction unit tests
├── Dockerfile                  # Multi-stage production container build
├── docker-compose.yml          # Docker Compose orchestration definition
├── requirements.txt            # Python dependencies
├── run_app.bat                 # Windows shortcut to launch app
├── run_tests.bat               # Windows shortcut to run test suite
└── install_deps.bat            # Windows shortcut to install dependencies
```

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.11+
* Git
* Virtual Environment (`venv` recommended)

### 1️⃣ Installation

#### Windows (Quick Setup)
Run the automated batch script:
```cmd
install_deps.bat
```

#### Manual Setup
```bash
# Create and activate virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🔄 Data Pipeline & Model Training

To re-run the complete data preprocessing, feature extraction, and model training workflow end-to-end:

```bash
python scripts/run_pipeline.py
```

### Running Individual Pipeline Steps
* **URL Preprocessing:** `python scripts/preprocess.py`
* **Feature Engineering:** `python scripts/feature_engineering.py`
* **Email Preprocessing:** `python scripts/preprocess_emails.py`
* **Blacklist Generation:** `python scripts/generate_blacklist.py`
* **Train URL Ensemble:** `python scripts/train_ensemble.py`
* **Train Email Model:** `python scripts/train_email_model.py`

---

## 🚀 Running the Web Application

### Local Development Server
Run `run_app.bat` or:
```bash
python -m app.app
```
Access the application in your web browser at: **`http://127.0.0.1:5000`**

### Running Automated Tests
Run `run_tests.bat` or:
```bash
python -m pytest
```

---

## 📡 API Reference

### Analyze URL
Analyzes a URL for phishing risk, returning probabilities and diagnostic explanations.

* **Endpoint:** `/api/analyze`
* **Method:** `POST`
* **Content-Type:** `application/json`

#### Request Payload
```json
{
  "url": "http://suspicious-bank-login.com/secure/login.php"
}
```

#### Success Response (`200 OK`)
```json
{
  "url": "http://suspicious-bank-login.com/secure/login.php",
  "decision": "Phishing",
  "ml_probability": 0.942,
  "risk_score": 85,
  "explanation": {
    "ml_detail": "High ML probability score (0.942) indicating structural phishing patterns.",
    "risk_breakdown": [
      "Domain age is under 30 days.",
      "Contains suspicious keyword: 'login'",
      "IP address host pattern detected."
    ]
  }
}
```

---

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)
```bash
docker-compose up --build -d
```
The application will be accessible at `http://localhost:5000`.

### Using Docker Directly
```bash
docker build -t secure-sight:latest .
docker run -d -p 5000:5000 --name secure-sight secure-sight:latest
```

---

## 🛡️ Security Implementation
* **Content Security Policy (CSP):** Enforced via Flask `after_request` middleware to restrict resource origins.
* **Clickjacking Protection:** `X-Frame-Options: DENY` header enabled on all responses.
* **File Upload Defense:** Validates MIME types, limits uploads to ≤ 5 MB, and sanitizes filenames using `werkzeug.utils.secure_filename`.
* **Non-Root Execution:** Docker image creates and runs under unprivileged `appuser` for production hardening.

---

## 🔍 SEO & Discoverability

Secure Sight uses the following SEO best practices in the web UI:
- Descriptive `<title>` and `<meta name="description">` on every page.
- Keyword-rich meta tags covering: *phishing detection, cyber threat intelligence, URL safety scanner, deepfake image detection, AI cybersecurity*.
- **Open Graph** tags for rich social media previews.
- **JSON-LD Schema** (`WebApplication` type) for structured data and search engine understanding.
- Semantic HTML5 with `<header>`, `<main>`, `<section>`, and `<footer>` elements.
- Single `<h1>` per page with a proper heading hierarchy.

---

## 📄 License & Attribution
© 2026 Secure Sight. Developed for Academic Research and Cybersecurity Awareness.
