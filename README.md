# Sentinel-IOC-Toolkit 🛡️

A simple tool to automate IOC (IP, URL, email, domain, hash, and CVE ID) extraction from logs.

---

## Why I built this

As a Blue Team student, I noticed that manual log analysis takes time and is repetitive.  
For example, when an alert appears, you often need to copy IPs and check them manually on platforms like VirusTotal.

This project is my attempt to reduce that manual work and better understand how log analysis works in practice.

---

## 🛠️ How it works

The project is split into two parts:

**Python Engine**
- Extracts IPs, URLs, email addresses, domains, CVE IDs, and MD5/SHA1/SHA256 hashes from log files using regex
- Outputs findings and per-type indicator counts into JSON format

**Java Interface (in progress)**
- Displays extracted data in a simple table
- Helps to quickly see which entries might be suspicious

---

## Current Features

- Extract IP addresses from raw logs
- Extract bare domains without duplicating hosts already captured as URLs
- Extract email-address indicators without counting mail domains as separate bare domains
- Extract CVE identifiers from alert text and normalize them to uppercase
- Extract MD5, SHA1, and SHA256 file hash indicators
- Summarize how many indicators were found by type
- Normalize common defanged IOCs such as `hxxp://` and `[.]`
- Basic detection of URLs / strings
- JSON output for further processing
- Optional AbuseIPDB enrichment when an API key is configured

---

## Running locally

Install the optional Python dependencies when you want AbuseIPDB enrichment:

```bash
python3 -m pip install -r requirements.txt
```

Create a local `.env` file from the example and set your own key:

```bash
cp .env.example .env
```

The expected variable name is:

```text
ABUSEIPDB_API_KEY=YOUR_API_KEY
```

The extractor can still parse local IOCs without this key; reputation fields will show that no API key is configured.

Run the Python parser against a local file:

```bash
cd python-backend
python3 extractor.py ../test.txt
```

You can pass any log or text file path:

```bash
python3 extractor.py /path/to/alert.log
```

---

## 📂 Project Structure

/python-backend – log parsing logic  
/java-frontend – GUI (in progress)  
/samples – test log files  

---

## 📅 Roadmap

- [x] Create project structure and README  
- [x] Improve regex (IPv4 / IPv6)  
- [x] Connect to AbuseIPDB API  
- [x] Add simple risk scoring  
- [x] Build Java GUI  

---
## 👨‍💻 Author
**Tao(0xTaoZ)**
Cybersecurity student | Aspiring Blue Team
