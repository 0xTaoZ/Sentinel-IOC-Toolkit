import re
import json
import os
import requests
from dotenv import load_dotenv # 用來安全地讀取你的 API Key

# 1. 初始化設定：讀取 .env 檔案中的 API Key
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

# --- 2. Rules to find threat (IOCs) ---
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
        """ 向 AbuseIPDB 查詢該 IP 是否惡意 (API Enrichment) """
        if not API_KEY:
            return {"error": "No API Key found"}

        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': API_KEY}

        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return {
                    "score": data['data']['abuseConfidenceScore'], # 0-100 的風險分
                    "country": data['data']['countryCode']         # 國家代碼
                }
            return {"error": f"API Error {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def start_scan(self):
        """ 讀取文件，識別 IOC，並對 IPv4 進行聯網分析 """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for name, rule in PATTERNS.items():
                    found = list(set(re.findall(rule, content)))
                    
                    # 關鍵升級：如果是 IPv4，我們不只列出來，還要聯網查它！
                    if name == "ipv4":
                        enriched_ips = []
                        for ip in found:
                            print(f"[*] Checking reputation for: {ip}")
                            rep = self.check_ip_reputation(ip)
                            enriched_ips.append({
                                "value": ip,
                                "analysis": rep
                            })
                        self.report["findings"][name] = enriched_ips
                    else:
                        self.report["findings"][name] = found
            
            return self.report
        except Exception as e:
            return {"error": str(e)}

    def save_to_json(self, output_name="result.json"):
        with open(output_name, 'w') as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Done! Analysis saved to {output_name}")

# --- 3. Run the tool ---
if __name__ == "__main__":
    target_log = "../samples/test_access.log"
    
    if os.path.exists(target_log):
        my_tool = SentinelEngine(target_log)
        
        # 啟動掃描（包含聯網查詢）
        print("[*] Sentinel-IOC Engine Starting...")
        data = my_tool.start_scan()
        
        # 打印結果到屏幕
        print(json.dumps(data, indent=4))
        
        # 保存結果文件
        my_tool.save_to_json()
    else:
        print(f"[!] Error: Cannot find {target_log}")

