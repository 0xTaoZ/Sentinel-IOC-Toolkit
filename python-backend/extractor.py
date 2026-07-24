import re
import json
import os
try:
    import requests
except ImportError:
    requests = None

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY") or os.getenv("ABUSEIPDB_KEY")

PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "ipv6": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*',
    "domain": r'(?<!://)\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b'
}

FILE_EXTENSION_SUFFIXES = {
    "bat",
    "class",
    "dll",
    "exe",
    "jar",
    "java",
    "js",
    "json",
    "log",
    "png",
    "py",
    "sh",
    "txt",
    "zip",
}

def normalize_defanged_iocs(content):
    normalized = re.sub(r"\bhxxps://", "https://", content, flags=re.IGNORECASE)
    normalized = re.sub(r"\bhxxp://", "http://", normalized, flags=re.IGNORECASE)
    normalized = normalized.replace("[.]", ".")
    return normalized

def is_valid_ipv4(value):
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def extract_matches(rule, content):
    matches = []
    seen = set()
    for match in re.finditer(rule, content):
        value = match.group(0)
        if value not in seen:
            matches.append(value)
            seen.add(value)
    return matches

def extract_domains(content):
    url_spans = [match.span() for match in re.finditer(PATTERNS["url"], content)]
    matches = []
    seen = set()
    for match in re.finditer(PATTERNS["domain"], content):
        start, end = match.span()
        if any(url_start <= start and end <= url_end for url_start, url_end in url_spans):
            continue
        value = match.group(0)
        if value.rsplit(".", 1)[-1].lower() in FILE_EXTENSION_SUFFIXES:
            continue
        if value not in seen:
            matches.append(value)
            seen.add(value)
    return matches

class SentinelEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.report = {"target_file": os.path.basename(file_path), "findings": {}}

    def check_ip_reputation(self, ip_address):
        """ Fetch reputation data from AbuseIPDB """
        if not API_KEY: return {"error": "No API Key"}
        if requests is None: return {"error": "requests is not installed"}
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': API_KEY}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return {"score": data['data']['abuseConfidenceScore'], "country": data['data']['countryCode']}
        except: return {"error": "Connection Failed"}
        return {"score": 0, "country": "Unknown"}

    def get_risk_level(self, score):
        """ Categorize risk based on score and provide advice """
        if score >= 80:
            return {"level": "CRITICAL", "action": "BLOCK IMMEDIATELY", "color": "RED"}
        elif score >= 40:
            return {"level": "SUSPICIOUS", "action": "MONITOR TRAFFIC", "color": "ORANGE"}
        else:
            return {"level": "CLEAN", "action": "NO ACTION REQUIRED", "color": "GREEN"}

    def start_scan(self):
        """ Scan file and perform risk scoring """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = normalize_defanged_iocs(f.read())
                for name, rule in PATTERNS.items():
                    found = extract_domains(content) if name == "domain" else extract_matches(rule, content)
                    if name == "ipv4":
                        found = [ip for ip in found if is_valid_ipv4(ip)]
                    if name == "ipv4":
                        enriched = []
                        for ip in found:
                            rep = self.check_ip_reputation(ip)
                            risk = self.get_risk_level(rep.get("score", 0))
                            enriched.append({
                                "value": ip,
                                "reputation": rep,
                                "risk_analysis": risk,
                                "firewall_rule": f"iptables -A INPUT -s {ip} -j DROP" if risk['level'] == "CRITICAL" else "N/A"
                            })
                        self.report["findings"][name] = enriched
                    else:
                        self.report["findings"][name] = found
            return self.report
        except Exception as e: return {"error": str(e)}

    def save_results(self):
        with open("result.json", "w") as f:
            json.dump(self.report, f, indent=4)
        print("[+] Analysis complete. JSON report updated with Risk Levels.")

if __name__ == "__main__":
    target = "../samples/test_access.log"
    if os.path.exists(target):
        engine = SentinelEngine(target)
        print("[*] Running Deep Analysis...")
        engine.start_scan()
        engine.save_results()
    else: print(f"Error: {target} not found.")
