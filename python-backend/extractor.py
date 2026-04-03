import re
import json
import os

# --- 1. Rules to find threat (IOCs) ---
# These are like search filters for IPs, Links, and File Hashes
# added "ipv6" to catch more advanced hacker addresses
PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    # This is the IPv6 pattern - it looks messy but it works for hex addresses
    "ipv6": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b'
}

class SentinelEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        # A dictionary to store what we find
        self.report = {
            "target_file": os.path.basename(file_path),
            "findings": {}
        }

    def start_scan(self):
        """ Read the file and find matches """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for name, rule in PATTERNS.items():
                    # Find all matches and remove duplicates using set()
                    found = list(set(re.findall(rule, content)))
                    self.report["findings"][name] = found
            
            return self.report
        except Exception as e:
            return {"error": str(e)}

    def save_to_json(self, output_name="result.json"):
        """ Save everything into a JSON file for Java to read later """
        with open(output_name, 'w') as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Done! Results saved to {output_name}")

# --- 2. Run the tool ---
if __name__ == "__main__":
    # Path to your test log file
    target_log = "../samples/test_access.log"
    
    # Check if the file exists before starting
    if os.path.exists(target_log):
        # Create the tool
        my_tool = SentinelEngine(target_log)
        
        # Start searching
        data = my_tool.start_scan()
        
        # Show results on screen
        print(f"[*] Scanning: {target_log}")
        print(json.dumps(data, indent=4))
        
        # Save the result file
        my_tool.save_to_json()
    else:
        print(f"[!] Error: Cannot find {target_log}")
        import requests  # Use this to talk to the internet

# This function will asks AbuseIPDB: "Is this IP bad?"
def check_ip_reputation(ip_address, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # These are the professional parameters required by AbuseIPDB
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    try:
        # Send the request to the website
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            # We want the "abuseConfidenceScore" (0-100)
            score = data['data']['abuseConfidenceScore']
            country = data['data']['countryCode']
            return {"score": score, "country": country}
        else:
            return {"error": "API Request Failed"}
            
    except Exception as e:
        return {"error": str(e)}
