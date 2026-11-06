# 🔍 Cyber Reconnaissance Tool

<p align="center">
  <strong>An Automated OSINT & Network Reconnaissance Platform</strong>
  <br />
  Built with Python, Flask, HTML, CSS, and JavaScript.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-Backend-black?style=for-the-badge&logo=flask" />
  <img src="https://img.shields.io/badge/JavaScript-Frontend-yellow?style=for-the-badge&logo=javascript" />
  <img src="https://img.shields.io/badge/OSINT-Reconnaissance-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

---

## 📌 Overview

**Cyber Reconnaissance Tool** is a full-stack cybersecurity reconnaissance platform designed to automate the initial information-gathering phase of security assessments.

The application collects publicly available information about a target domain or IP address, including DNS records, network exposure, HTTP response headers, geolocation intelligence, and WHOIS registration details.

It combines multiple reconnaissance techniques into a single web-based dashboard, making preliminary security assessments easier to perform and understand.

> Designed for cybersecurity learners, security researchers, and authorized penetration-testing environments.

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 Domain Normalization | Accepts domains and URLs with automatic normalization |
| 🔎 DNS Enumeration | Resolves IPv4 and IPv6 addresses |
| 🔌 Port Scanning | Identifies accessible common network ports |
| 🛡️ HTTP Analysis | Retrieves HTTP response headers and status codes |
| 🔐 Security Header Analysis | Identifies missing HTTP security headers |
| 🌍 Geo-IP Intelligence | Retrieves country, city, region, and ISP information |
| 📋 WHOIS Lookup | Collects domain registration information |
| 📊 Recon Dashboard | Displays reconnaissance results in an organized interface |
| ⚡ Concurrent Scanning | Uses multithreading for faster port checks |
| ❤️ Health Monitoring | Provides a backend health-check endpoint |

## 🧰 Technology Stack

**Backend**
- Python 3.11
- Flask
- Flask-CORS
- Requests
- Socket
- Concurrent Futures
- python-whois

**Frontend**
- HTML5
- CSS3
- JavaScript (ES6+)

**External Intelligence**
- IPinfo API
- DNS resolution
- WHOIS services

## 🏗️ Project Architecture

```text
Cyber-Reconnaissance-Tool/
│
├── backend/
│   ├── app.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
└── README.md
```

## ⚙️ Getting Started

### Prerequisites

Make sure you have installed:

- Python 3.11 or later
- pip (Python package manager)
- Git
- A modern web browser

### 1. Clone the Repository

```bash
git clone https://github.com/Razer255/cybersecurity-reconnaissance-tool.git
```

### 2. Navigate to the Project

```bash
cd cybersecurity-reconnaissance-tool
```

### 3. Set Up the Backend

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

**Windows**
```bash
venv\Scripts\activate
```

**Linux / macOS**
```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the Flask Server

```bash
python app.py
```

The backend will run at:

```text
http://127.0.0.1:5000
```

### 6. Launch the Frontend

Open `frontend/index.html` using your browser or a local development server such as VS Code Live Server.

The application communicates with the Flask backend through its REST API.

## 🔌 API Documentation

### POST `/recon`

Performs reconnaissance against a supplied domain or IP address.

**Request**

```json
{
  "domain": "example.com"
}
```

**Response**

```json
{
  "target": "example.com",
  "ip": "93.184.216.34",
  "open_ports": [80, 443],
  "headers": {},
  "geo": {
    "country": "US",
    "org": "Example ISP"
  },
  "whois": {},
  "dns": {
    "ipv4": ["93.184.216.34"],
    "ipv6": []
  },
  "http": {
    "status_code": 200,
    "server": "Example Server",
    "security_headers": {},
    "missing_security_headers": []
  },
  "scan_info": {
    "ports_tested": [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443],
    "open_ports_count": 2,
    "status": "Completed"
  }
}
```

*Note: Example values are illustrative. Actual results depend on the target and network conditions.*

### GET `/health`

Checks whether the Flask backend is running.

**Response**

```json
{
  "status": "online",
  "service": "Cyber Recon Backend",
  "version": "2.0"
}
```

## 📸 Screenshots

Add your actual project screenshots here.

```markdown
![Dashboard](screenshots/dashboard.png)
![Reconnaissance Results](screenshots/recon-results.png)
```

## 🔐 Security & Responsible Usage

This project is developed strictly for educational purposes, authorized security testing, and legitimate cybersecurity research.

- Only scan domains and IP addresses you own or have explicit permission to assess.
- Do not use the tool for unauthorized network reconnaissance.
- Port scanning is limited to a predefined list of common ports.
- Public IP validation is implemented as a basic safeguard.
- Additional network-level restrictions are recommended before deployment.

The developer assumes no responsibility for misuse of this software.

## 🚀 Future Enhancements

- [ ] Subdomain Enumeration
- [ ] Advanced DNS Record Discovery
- [ ] SSL/TLS Certificate Analysis
- [ ] Technology Stack Fingerprinting
- [ ] CVE & Vulnerability Intelligence Integration
- [ ] Export Reports in PDF and JSON
- [ ] Historical Scan Results
- [ ] Interactive Network Visualization
- [ ] Enhanced Security Header Risk Scoring

## 👨‍💻 Author

**Rishipal Ghosh**

Cybersecurity | Ethical Hacking | Full-Stack Development

- GitHub: [@Razer255](https://github.com/Razer255)
- Project Repository: [Cyber Reconnaissance Tool](https://github.com/Razer255/cybersecurity-reconnaissance-tool)

---

<p align="center">
  <strong>Built for learning. Designed for security. Powered by curiosity. 🔐</strong>
</p>
