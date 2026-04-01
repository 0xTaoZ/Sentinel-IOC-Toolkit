# Sentinel-IOC-Toolkit 🛡️

### Why I built this?
As a Blue Team student, I realized that manual log analysis is a pain. When an alert hits, you waste 10 minutes just copying and pasting IPs into VirusTotal. I wanted a tool that does the "dirty work" for me. 

**Sentinel-IOC-Toolkit** is my project to bridge the gap between Python scripts and a usable security tool.

---

## 🛠️ The Logic (How it works)
The project is split into two parts:
1. **Python Engine:** A fast script to "grab" IPs, URLs, and Hashes from any messy text file using Regular Expressions (Regex).
2. **Java Interface:** A clean dashboard to manage these threats. Instead of looking at a black terminal, I want to see a clear table with risk levels.

### Current Features
- **Fast IOC Extraction:** No more manual searching.
- **Threat Tagging:** Automatically identifies if a string is an IP or a URL.
- **Blue Team Focus:** Designed for incident responders, not just developers.

---

## 📂 Project Structure
- `/python-backend`: Contains the core logic for log parsing.
- `/java-frontend`: The GUI part (work in progress).
- `/samples`: Real-world log samples for testing.

---

## 📅 Roadmap
- [x] Create project structure and README.
- [ ] Finish Python Regex engine for IP extraction.
- [ ] Connect to AbuseIPDB API for real-time scoring.
- [ ] Build the Java Swing/JavaFX dashboard.

---

## 👨‍💻 Author
**Tao(0xTaoZ)**
*Cybersecurity student*
