import re

# Target log for testing
data = "Alert: 192.168.1.1 and 10.0.0.5 detected."

# IPv4 Regex Pattern
ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def main():
    ips = re.findall(ip_regex, data)
    print(f"Results: {ips}")

if __name__ == "__main__":
    main()
