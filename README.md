# Sentinel-IOC-Toolkit 🛡️

A simple tool to automate IOC (IP, URL, Hash) extraction from logs.

---

## Why I built this

As a Blue Team student, I noticed that manual log analysis takes time and is repetitive.  
For example, when an alert appears, you often need to copy IPs and check them manually on platforms like VirusTotal.

This project is my attempt to reduce that manual work and better understand how log analysis works in practice.

---

## 🛠️ How it works

The project is split into two parts:

**Python Engine**
- Extracts IPs, URLs, and hashes from log files using regex
- Outputs results into JSON format

**Java Interface (in progress)**
- Displays extracted data in a simple table
- Helps to quickly see which entries might be suspicious

---

## Current Features

- Extract IP addresses from raw logs
- Basic detection of URLs / strings
- JSON output for further processing

---

## 📂 Project Structure

/python-backend – log parsing logic  
/java-frontend – GUI (in progress)  
/samples – test log files  

---

## 📅 Roadmap

- [x] Create project structure and README  
- [ ] Improve regex (IPv4 / IPv6)  
- [ ] Connect to AbuseIPDB API  
- [ ] Add simple risk scoring  
- [ ] Build Java GUI  

---
## 👨‍💻 Author
**Tao(0xTaoZ)**
Cybersecurity student | Aspiring Blue Team
