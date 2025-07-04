
# 🛡️ Cybersecurity Analysis Toolkit

The **Cybersecurity Analysis Toolkit** is a powerful, web-based application designed to equip cybersecurity professionals, SOC analysts, and learners with a unified interface for analyzing IP addresses, scanning suspicious URLs, and decoding email headers.

It simplifies threat detection by integrating **GeoIP threat intelligence**, **URL scanning**, and **email header analysis** using a responsive UI and a Python Flask-powered backend.

---

## 🚀 Core Functionalities

### 🌍 GeoIP Locator
- **Purpose**: Retrieves geographic and network information for any IP address.
- **Threat Detection**:
  - Checks for **Tor exit nodes**
  - Matches against **known malicious IPs**
  - Uses **VirusTotal API** to determine threat level (High, Medium, Low, Clean)

### 🔗 Malicious URL Scanner
- **Purpose**: Analyzes URLs for phishing or malware indicators.
- **Detection Methods**:
  - Heuristic analysis (unusual structure, phishing patterns)
  - Integration with **VirusTotal** for deep intelligence
  - Outputs **risk score** and **threat category**

### 📋 Email Header Analyzer
- **Purpose**: Parses raw email headers to reveal delivery paths and spoofing.
- **What It Does**:
  - Extracts sender and relay IPs
  - Checks SPF, DKIM, DMARC authentication
  - Flags **anomalies**, **spoofing attempts**, and suspicious headers

---

## 🔁 Operational Flow

1. **User Input**: IP address, URL, or raw email headers are submitted via a clean web UI.
2. **API Communication**: JavaScript sends data to Flask backend endpoints.
3. **Backend Modules**:
   - `GeoIPlocator.py`: IP info + threat intelligence
   - `URLscanner.py`: Heuristic + VirusTotal URL scan
   - `headeranalysis.py`: Parses headers and verifies sender legitimacy
4. **Response**: Flask sends JSON analysis results back to the frontend.
5. **UI Output**: Results are dynamically rendered with color-coded risk indicators.

---

## 🧪 Technologies Used

### Backend – Python Flask
- `Flask`: Lightweight API routing
- `requests`: API calls to VirusTotal and threat feeds
- `ipaddress`: IP validation and handling
- `email`: Parses headers natively
- `dataclasses`: For structured data
- `python-dotenv`: Secure API key storage
- `flask-cors`: Enables cross-origin access

### Frontend – HTML, CSS, JavaScript
- `HTML5`: Clean structure
- `CSS3`: Responsive layout
- `JavaScript`: Dynamic interaction & async backend communication

---

## 🛠️ Setup Instructions

### 1. Clone the Repository
```bash
git clone <your-repository-url>
cd Cybersecurity-Analysis-Toolkit
```

### 2. Backend Setup

Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. Configure VirusTotal API
Create a `.env` file in the root directory:
```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

> ⚠️ Make sure `.env` is excluded in `.gitignore` to avoid exposing your API key.

---

### 4. Run the Flask Server
```bash
python app.py
```

Server runs at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### 5. Frontend Access
Open `UI.html` in your browser.

---

## 💻 Usage

| Tool                  | Description |
|-----------------------|-------------|
| **Phishing Detector** | Paste full email content to detect spoofing/phishing |
| **GeoIP Locator**     | Enter IP to get location, reputation, and threat score |
| **URL Scanner**       | Submit suspicious URL for live risk analysis |
| **Header Analyzer**   | Paste raw email headers to trace route and verify auth |

---

## 📂 Project Structure

```
.
├── app.py               # Main backend API handler
├──templates
     └── UI.html         # Frontend UI (HTML, CSS, JS)
├── GeoIPlocator.py      # IP geolocation + threat intel logic
├── headeranalysis.py    # Email header parser + validation
├── URLscanner.py        # URL scanner + VirusTotal integration
├── requirements.txt     # Python dependencies
└── .env                 # Sample environment variable config

```

---

## 🤝 Contributing

1. Fork the repo  
2. Create your feature branch  
   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit your changes  
   ```bash
   git commit -m 'Add new feature'
   ```
4. Push to your branch  
   ```bash
   git push origin feature/your-feature
   ```
5. Submit a **Pull Request**

---
<!-- 
## 📬 Contact
Have questions or want to contribute ideas?  
Open an issue or reach out via pull request. -->
