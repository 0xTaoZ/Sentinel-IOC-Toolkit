import re
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "ipv6": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b'
}

class SentinelEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.report = {"target_file": os.path.basename(file_path), "findings": {}}

    def check_ip_reputation(self, ip_address):
        """ Fetch reputation data from AbuseIPDB """
        if not API_KEY: return {"error": "No API Key"}
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
                content = f.read()
                for name, rule in PATTERNS.items():
                    found = list(set(re.findall(rule, content)))
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
