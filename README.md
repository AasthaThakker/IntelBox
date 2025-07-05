
# 🛡️ IntelBox

The **IntelBox Toolkit** is a comprehensive, web-based application built for **SOC analysts**, **cybersecurity professionals**, and **enthusiasts**. It combines powerful threat analysis capabilities including IP geolocation, URL scanning, phishing detection, email header parsing, and domain intelligence—all within a user-friendly interface.

---

## 🚀 Features

### 🌍 GeoIP Locator
- Retrieves geographic and ASN info for any IP
- Detects:
  - **Tor Exit Nodes**
  - **Known Malicious IPs**
  - VirusTotal-based reputation scoring

### 🔗 Malicious URL Scanner
- Heuristically evaluates URLs for phishing/malware
- Integrates with **VirusTotal**
- Returns **risk score** and **threat classification**

### 📋 Email Header Analyzer
- Parses raw headers to trace delivery route
- Verifies:
  - **SPF**, **DKIM**, **DMARC**
  - Relay and source IPs
- Flags spoofing/suspicious behavior

### 🎣 AI-Based Phishing Detector
- Uses machine learning to classify emails as:
  - **Phishing**, **Spam**, or **Safe**
- Analyzes:
  - Subject & body content
  - Obfuscated URLs, suspicious TLDs
- Returns **risk score**, **confidence**, and **explanation**

### 🌐 DNS & WHOIS Intelligence
- Retrieves:
  - **A, MX, SPF, NS** DNS records
  - WHOIS data (registration, expiration, registrar)
- Flags:
  - **Recently registered** or **short-lifecycle domains**
  - Domain anomalies or bad reputation

---

## 🔁 Operational Workflow

1. **User Inputs** IP, URL, email headers/content, or domain
2. **Frontend** sends data via JavaScript to Flask endpoints
3. **Backend Modules** process:
   - `GeoIPlocator.py`
   - `URLscanner.py`
   - `headeranalysis.py`
   - `phishing_detector.py`
   - `dns_whois.py`
4. **Flask API** returns JSON results
5. **Frontend UI** displays analysis with risk indicators

---

## 🧪 Tech Stack

### 🖥️ Backend – Python (Flask)
- `Flask`, `requests`, `email`, `dataclasses`, `joblib`
- `scikit-learn`: ML pipeline
- `dns.resolver`, `whois`: DNS & domain queries
- `python-dotenv`: Secure key storage

### 🌐 Frontend – HTML + JS
- `HTML5`, `CSS3`, `JavaScript`
- Responsive, minimal UI in `UI.html`

---

## 🛠️ Getting Started

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd Cybersecurity-Analysis-Toolkit
```

### 2. Set Up Python Virtual Environment
```bash
python -m venv venv
# Activate:
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Keys
Create a `.env` file:
```env
VIRUSTOTAL_API_KEY=your_api_key_here
```
✅ Ensure `.env` is added to `.gitignore`.

### 5. Run the Flask Server
```bash
python app.py
```
Server is accessible at: `http://127.0.0.1:5000`

### 6. Launch Frontend
Open `templates/UI.html` in a browser.

---

## 💻 Usage Guide

| Tool              | Input Required         | Output Summary                                  |
|------------------|------------------------|--------------------------------------------------|
| **Phishing Detector** | Full email text       | Classification (Phishing/Spam/Safe), Risk Score  |
| **GeoIP Locator**     | IP address            | Geolocation + Threat Score + Flags               |
| **URL Scanner**       | Suspicious URL        | VirusTotal Scan + Risk & Threat Classification   |
| **Header Analyzer**   | Raw email headers     | Relay IPs + Auth Results + Spoofing Flags        |
| **Domain Analyzer**   | Domain name           | DNS records + WHOIS info + Lifecycle Risk        |

---

## 📂 Project Structure

```
Cybersecurity-Analysis-Toolkit/
│
├── app.py                   # Flask app main entry
├── GeoIPlocator.py          # IP geolocation & threat detection
├── headeranalysis.py        # Email header parser
├── URLscanner.py            # URL threat scanner
├── phishing_detector.py     # ML-based email classification
├── dns_whois.py             # Domain info & DNS analysis
├── requirements.txt         # Python dependencies
├── phishing_model.joblib    # Trained phishing detection model
├── phishing_vectorizer.joblib # TF-IDF vectorizer
├── .env                     # VirusTotal API key config
└── templates/
    └── UI.html              # Web UI (HTML + JS)
```

---

## 🤝 Contributing

We welcome contributions!

1. Fork the repository
2. Create a feature branch
   ```bash
   git checkout -b feature/your-feature
   ```
3. Make your changes & commit
   ```bash
   git commit -m "Added feature: ..."
   ```
4. Push and submit a pull request
   ```bash
   git push origin feature/your-feature
   ```
