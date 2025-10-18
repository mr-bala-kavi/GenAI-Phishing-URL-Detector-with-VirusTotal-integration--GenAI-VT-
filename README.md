# 🛡️ AI Phishing URL Detector (GPT + VirusTotal)

A powerful web application that combines OpenAI's advanced language models with VirusTotal's threat intelligence to detect and analyze phishing URLs with high accuracy.

---

## 🌟 Features

### 🔍 Multi-Layer Detection

* **AI-Powered Analysis:** Uses GPT models to heuristically analyze URL structure and content.
* **VirusTotal Integration:** Checks against 70+ antivirus engines and threat intelligence feeds.
* **Combined Verdict Logic:** Intelligent fusion of both signals for maximum accuracy.

### 📊 Advanced Capabilities

* **Single URL Analysis:** Quick analysis of individual URLs with detailed breakdown.
* **Batch CSV Processing:** Process thousands of URLs from CSV files.
* **Historical Tracking:** SQLite database stores all scans with feedback mechanism.
* **Real-time Results:** Live progress tracking for batch operations.

### 🛡️ Security & Privacy

* Local SQLite database (no cloud storage of sensitive data).
* Secure API key management via Streamlit secrets.
* No permanent storage of scanned URLs or content.

---

## 🚀 Quick Start

### Prerequisites

* Python 3.8+
* OpenAI API key
* VirusTotal API key (optional but recommended)

### Installation

1. Clone or download the project files.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up API keys:

Create `.streamlit/secrets.toml`:

```toml
OPENAI_API_KEY = "your-openai-api-key-here"
VIRUSTOTAL_API_KEY = "your-virustotal-api-key-here"
```

4. Run the application:

```bash
streamlit run app.py
```

### 🔧 Configuration

**API Keys**

| Service    | Required   | How to Get      |
| ---------- | ---------- | --------------- |
| OpenAI     | ✅ Yes      | OpenAI Platform |
| VirusTotal | ❌ Optional | VirusTotal API  |

**Environment Variables (Alternative)**

```bash
export OPENAI_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
```

---

## 📖 Usage

### Single URL Analysis

1. Enter a URL in the text input field.
2. Click "Analyze".
3. View comprehensive results including:

   * Final combined verdict
   * AI analysis with confidence score
   * VirusTotal reputation data
   * Technical URL features
   * Recommended actions

### Batch CSV Processing

1. Prepare a CSV file with a column named `url`.
2. Upload via the batch section.
3. Monitor real-time progress.
4. Download results as CSV.

### View History

* Access scan history from sidebar.
* Download historical data.
* Provide feedback on detection accuracy.

---

## 🧠 How It Works

**Detection Pipeline**

1. **URL Feature Extraction:** Analyzes URL structure, domain, TLD, suspicious patterns.
2. **Content Analysis:** Fetches and analyzes HTML content (optional).
3. **AI Assessment:** GPT model evaluates heuristics and provides verdict.
4. **VirusTotal Check:** Queries global threat intelligence database.
5. **Signal Fusion:** Combines AI and VT signals using priority logic.

**Verdict Logic**

```python
Priority 1: VT detects threat → Use VT verdict
Priority 2: Both safe → Safe
Priority 3: VT clean but AI flags → Suspicious (possible zero-day)
Priority 4: VT unavailable → Use AI analysis only
```

### 📊 Output Interpretation

**Verdict Levels**

* ✅ Safe: Low risk, legitimate website
* ⚠️ Suspicious: Requires caution, potential phishing
* 🚨 Malicious: High confidence phishing/malware

**Data Provided**

* AI confidence score (0-100)
* Detailed explanation of findings
* VirusTotal detection statistics
* Technical URL analysis
* Recommended actions

---

## 💾 Data Storage

SQLite schema includes:

* URL and timestamp
* AI verdict, score, and explanation
* VirusTotal verdict and statistics
* Combined final verdict
* User feedback (optional)

---

## ⚠️ Important Notes

**Rate Limits**

* VirusTotal: 500 requests/day (free tier)
* OpenAI: Depends on your plan
* Batch processing includes delays to respect limits

**Privacy & Security**

* ✅ URLs are only sent to OpenAI and VirusTotal APIs
* ✅ No permanent storage of HTML content
* ✅ Local database only stores metadata
* ❌ Do not scan URLs containing sensitive credentials

**Limitations**

* HTML fetching may fail for some sites (anti-bot protection)
* VirusTotal free tier has limited request quota
* AI models may have false positives/negatives

---

## 🛠️ Technical Details

**Built With**

* Frontend: Streamlit
* AI: OpenAI GPT-4o-mini / GPT-4o
* Threat Intel: VirusTotal v3 API
* Database: SQLite
* Language: Python 3.8+

**Key Dependencies**

* `streamlit` - Web interface
* `openai` - AI model integration
* `requests` - API communications
* `tldextract` - URL parsing
* `pandas` - Data processing

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for:

* Bug fixes
* Feature requests
* Documentation improvements
* Detection logic enhancements

---

## 📄 License

This project is intended for educational and cybersecurity purposes. Use responsibly and in compliance with all applicable laws and terms of service for integrated APIs.

---

## 🆘 Support

* Check API keys are correctly configured
* Verify network connectivity to APIs
* Check rate limits haven't been exceeded
* Review Streamlit logs for detailed error messages

*Disclaimer: This tool is for cybersecurity analysis. Always verify critical security decisions through multiple channels and follow your organization's security protocols.*

---

## 👤 Created By

**Kavi.s_Network**

**Instagram:** ![Instagram](https://img.shields.io/badge/Instagram-@kavi.s_network-E4405F?style=flat\&logo=instagram\&logoColor=white) [kavi.s_network](https://www.instagram.com/kavi.s_network)

**YouTube:** ![YouTube](https://img.shields.io/badge/YouTube-Kavi's_Network-FF0000?style=flat\&logo=youtube\&logoColor=white) [Kavi's Network](https://youtube.com/@kavis_network?si=9bKgtdQ0jtthp3xh)

**LinkedIn:** ![LinkedIn](https://img.shields.io/badge/LinkedIn-Balakavi-0077B5?style=flat\&logo=linkedin\&logoColor=white) [Balakavi](https://www.linkedin.com/in/balakavi/)
