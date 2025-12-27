

# 🔊 CALLGraph — OSINT & Voice Forensics for Communication Threats

**CALLGraph** is a modular OSINT and forensic framework that analyzes phone numbers, SIP logs, domains, and voice samples to detect spoofing, VoIP scams, and suspicious communication patterns.  
It combines telecom metadata, SIP header analysis, network intelligence, and voice similarity scoring for rapid threat assessment.

***

## 🚀 What CALLGraph Does

- **📞 Number Intelligence:** Parses phone numbers for carrier, type, and reassignment status.
- **📡 SIP & Network Intelligence:** Extracts IPs, ports, and caller IDs from SIP logs, scans open ports (5060, 5061, 80, 443, 8080), and flags spoofing using `From` vs `P-Asserted-Identity` mismatches.
- **🌐 Domain Intelligence:** Gathers WHOIS/DNS info and assesses domain trust.
- **🎤 Voice Similarity Analysis:** Compares voice samples using deep-learning embeddings to detect impersonation or cloned voices.

Each module outputs a **Threat Confidence Score (Low/Medium/High)** and a one-line summary.

***

## 🧠 How It Works

### SIP Log Analysis
- **SIP Parsing:** Uses regex to extract IPs, ports, and caller IDs from SIP logs or PCAP files (via `tshark`).
- **Port Scanning:** Scans for open SIP and web ports using Python sockets.
- **Geolocation:** Enriches IPs with location, ASN, and privacy data using the **IPinfo API**.
- **Spoof Detection:** Flags mismatches between `From` and `P-Asserted-Identity` headers.
- **Threat Scoring:** Scores threats based on open ports, spoofing, hosting type, and suspicious patterns.

### Voice Similarity
- Uses **Resemblyzer** to extract voice embeddings.
- Computes cosine similarity to compare two voice samples.

---

## 🧩 Key Features

- Modular CLI tools for each analysis type.
- Automated threat scoring and summary generation.
- Supports both SIP text logs and PCAP files (via `tshark`).
- IP geolocation and ASN enrichment via IPinfo API.
- Voice similarity analysis with deep learning.
- Extensible Flask backend for web integration.

***

## ⚙️ Tech Stack

| Category | Tools / Libraries |
|-----------|-------------------|
| **Backend Framework** | Flask, Flask-CORS, Flask-Limiter, Gunicorn |
| **Networking & APIs** | Twilio, Requests, tshark (Wireshark) |
| **Parsing & Analysis** | Regex, Python sockets, subprocess, ThreadPoolExecutor |
| **IP Intelligence** | IPinfo API (geolocation, ASN, privacy) |
| **Voice Analysis** | Resemblyzer, NumPy, scikit-learn |
| **Deployment** | python-dotenv, Gunicorn |
| **Language** | Python 3.10+

**Requirements:**
```
flask>=3.0.0
flask-cors>=4.0.0
flask-limiter>=3.5.0
limits>=3.13.0
twilio>=9.0.0
requests>=2.31.0
phonenumbers>=8.13.0
dnspython>=2.4.0
python-dotenv>=1.0.0
gunicorn>=21.0.0
```

***

## 🧾 Example Output

| IP | Ports | Spoof | Score | From | To | Location / ASN |
|-----|-------|-------|-------|------|-----|----------------|
| 192.168.1.1 | 5060 | Yes | High | sip:user@domain.com | sip:target@domain.com | New York, US | Hosting Provider (ASN: AS12345) |

**Summary:**  
"Caller ID spoofing detected, SIP port 5060 open, likely malicious."

***

## 🎯 Why It’s Innovative

- Covers telecom, network, domain, and voice layers of OSINT.
- Real-time, actionable threat scoring.
- Modular design for independent demos or unified dashboard.
- Integrates open-source tools and APIs for scalable intelligence.

***

## 🧭 Setup

```bash
# Clone and install dependencies
git clone https://github.com/<username>/CALLGraph.git
cd CALLGraph
pip install -r requirements.txt

# Run development server
python app.py
```

***

## 🏁 Impact

**CALLGraph** empowers investigators to trace, analyze, and score digital communication threats — from number spoofing to cloned voices — in one unified OSINT toolkit.

> “From SIP logs to voice samples — CALLGraph connects the dots in modern communication forensics.”  

