import re
import json
import os
import argparse
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
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b',
    "domain": r'(?<!://)\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "cve": r'\b[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,7}\b'
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
    excluded_spans = [
        match.span()
        for pattern_name in ("url", "email")
        for match in re.finditer(PATTERNS[pattern_name], content)
    ]
    matches = []
    seen = set()
    for match in re.finditer(PATTERNS["domain"], content):
        start, end = match.span()
        if any(span_start <= start and end <= span_end for span_start, span_end in excluded_spans):
            continue
        value = match.group(0)
        if value.rsplit(".", 1)[-1].lower() in FILE_EXTENSION_SUFFIXES:
            continue
        if value not in seen:
            matches.append(value)
            seen.add(value)
    return matches

def extract_cves(content):
    matches = []
    seen = set()
    for match in re.finditer(PATTERNS["cve"], content):
        value = match.group(0).upper()
        if value not in seen:
            matches.append(value)
            seen.add(value)
    return matches

class SentinelEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.report = {"target_file": os.path.basename(file_path), "findings": {}, "summary": {}}

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
                    if name == "domain":
                        found = extract_domains(content)
                    elif name == "cve":
                        found = extract_cves(content)
                    else:
                        found = extract_matches(rule, content)
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
                counts = {
                    name: len(values)
                    for name, values in self.report["findings"].items()
                }
                self.report["summary"] = {
                    "total_indicators": sum(counts.values()),
                    "counts": counts,
                }
            return self.report
        except Exception as e: return {"error": str(e)}

    def save_results(self):
        with open("result.json", "w") as f:
            json.dump(self.report, f, indent=4)
        print("[+] Analysis complete. JSON report updated with Risk Levels.")

def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract IOCs from a log or text file.")
    parser.add_argument("target", nargs="?", default="../test.txt", help="file to scan")
    args = parser.parse_args(argv)

    target = args.target
    if os.path.exists(target):
        engine = SentinelEngine(target)
        print("[*] Running Deep Analysis...")
        engine.start_scan()
        engine.save_results()
        return 0
    print(f"Error: {target} not found.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
