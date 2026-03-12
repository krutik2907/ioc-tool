# 🛡️ IOC Bulk Enrichment Tool

A threat intelligence platform built for SOC analysts to enrich Indicators of Compromise (IOCs) in bulk, map findings to the MITRE ATT&CK framework, and export incident reports.

**Live Demo:** [ioc-tool-krutik2907.vercel.app](https://ioc-tool-krutik2907.vercel.app)

---

## 🔍 What It Does

- Accepts bulk IOC input — IPs, URLs, domains, and file hashes
- Automatically detects IOC type
- Enriches each IOC using multiple threat intelligence sources simultaneously
- Maps findings to MITRE ATT&CK techniques, tactics, and mitigations
- Calculates a risk score for each IOC
- Exports a full incident report as CSV

---

## 🧰 Threat Intelligence Sources

| Source | Coverage |
|--------|----------|
| [VirusTotal](https://virustotal.com) | Malware, URLs, domains, file hashes — 90+ AV engines |
| [AbuseIPDB](https://abuseipdb.com) | IP reputation, abuse confidence score, ISP, country |
| [URLScan.io](https://urlscan.io) | Live URL scanning and screenshot capture |

---

## 🗺️ MITRE ATT&CK Mapping

Each IOC is automatically mapped to relevant MITRE ATT&CK techniques including:
- Technique ID and name (e.g. T1566.002 – Spearphishing Link)
- Tactic category (e.g. Initial Access, Command and Control)
- Full technique description
- Recommended mitigations (M-codes)

---

## 🚀 Tech Stack

- **Frontend:** React.js
- **Backend:** Vercel Serverless Functions (Node.js)
- **APIs:** VirusTotal v3, AbuseIPDB v2, URLScan.io
- **Deployment:** Vercel
- **Framework:** MITRE ATT&CK v14

---

## ⚙️ Run Locally

### Prerequisites
- Node.js v18+
- Free API keys from VirusTotal, AbuseIPDB, URLScan.io

### Setup
```bash
git clone https://github.com/krutik2907/ioc-tool.git
cd ioc-tool
npm install
```

Create a `.env` file in the root folder:
```
REACT_APP_VIRUSTOTAL_KEY=your_virustotal_key
REACT_APP_ABUSEIPDB_KEY=your_abuseipdb_key
REACT_APP_URLSCAN_KEY=your_urlscan_key
```
```bash
npm start
```

---

## 📁 Project Structure
```
ioc-tool/
├── api/
│   ├── virustotal.js      # Serverless proxy for VirusTotal API
│   ├── abuseipdb.js       # Serverless proxy for AbuseIPDB API
│   └── urlscan.js         # Serverless proxy for URLScan.io API
├── src/
│   └── App.jsx            # Main React application
└── package.json
```

---

## 📊 Sample Output

| IOC | Type | Verdict | Risk Score | VT Hits |
|-----|------|---------|------------|---------|
| 185.220.101.45 | IP | 🔴 MALICIOUS | 100% | 17/94 |
| 44d88612fea8a8f3... | Hash | 🔴 MALICIOUS | 88% | 67/76 |
| 194.165.16.11 | IP | 🔴 MALICIOUS | 65% | 13/94 |

---

## 👤 Author

**Krutik** — SOC Analyst  
[GitHub](https://github.com/krutik2907) · [LinkedIn](https://www.linkedin.com/in/krutikraut29/)

---

## ⚠️ Disclaimer

This tool is built for educational and portfolio purposes. All IOCs analyzed are for research only. Do not visit or interact with any malicious URLs directly.
```

---
