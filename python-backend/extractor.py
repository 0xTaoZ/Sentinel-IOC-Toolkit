import re
import json
import os
import requests
from dotenv import load_dotenv

# Load API Key from .env file
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

# --- 1. Patterns to identify Indicators of Compromise (IOCs) ---
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
        self.report = {
            "target_file": os.path.basename(file_path),
            "findings": {}
        }

    def check_ip_reputation(self, ip_address):
        """ Fetch risk score from AbuseIPDB API """
        if not API_KEY:
            return {"error": "API Key is missing"}

        api_url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': API_KEY}

        try:
            response = requests.get(api_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return {
                    "score": data['data']['abuseConfidenceScore'],
                    "country": data['data']['countryCode']
                }
            return {"error": f"API responded with code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def start_scan(self):
        """ Scan the log file and enrich IPv4 findings with API data """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for name, rule in PATTERNS.items():
                    found_items = list(set(re.findall(rule, content)))
                    
                    if name == "ipv4":
                        # If IPv4 is found, query the API for reputation
                        enriched_list = []
                        for ip in found_items:
                            print(f"[*] Checking IP reputation: {ip}")
                            analysis = self.check_ip_reputation(ip)
                            enriched_list.append({
                                "value": ip,
                                "analysis": analysis
                            })
                        self.report["findings"][name] = enriched_list
                    else:
                        self.report["findings"][name] = found_items
            
            return self.report
        except Exception as e:
            return {"error": str(e)}

    def save_results(self, output_file="result.json"):
        """ Export the final report to a JSON file """
        with open(output_file, 'w') as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Scan complete. Data saved to: {output_file}")

# --- Execution ---
if __name__ == "__main__":
    test_log = "../samples/test_access.log"
    
    if os.path.exists(test_log):
        engine = SentinelEngine(test_log)
        print("--- Sentinel-IOC Analysis Starting ---")
        
        scan_data = engine.start_scan()
        print(json.dumps(scan_data, indent=4))
        

