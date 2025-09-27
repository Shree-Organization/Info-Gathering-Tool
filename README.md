# 🔎 Info Gathering Tool

A simple Python-based **information gathering / OSINT tool** for domains and IPs.  
It collects:

- **WHOIS** information (registrant, registrar, creation/expiration dates, etc.)
- **DNS records** (A, MX, NS, TXT)
- **Geolocation** data of the target IP
- **Shodan** data (open ports, services, organization, OS) — requires API key

⚠️ **For educational and authorized security testing only.**  
Do **not** use this tool against systems you are not explicitly allowed to test.

---

## 🚀 Features

- Robust error handling (won’t crash if a lookup fails)
- Optional JSON output for easy parsing/reporting
- Reads Shodan API key from `--shodan-key` or `SHODAN_API_KEY` environment variable
- Command-line interface with helpful flags
---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/dhruva127/info-gathering.git
cd info-gathering
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


```
## 🛠 Usage

Create and activate a virtual environment
```
python3 -m venv venv
source venv/bin/activate
```
# Install dependencies
```
pip install -r requirements.txt
```
Basic example
```
python3 info_gathering.py -d example.com
```
Save results to a JSON file
```
python3 info_gathering.py -d example.com -o results.json

```
Provide a Shodan API key

Either via argument:
```
python3 info_gathering.py -d example.com -k YOUR_SHODAN_KEY

```
Or via environment variable (recommended):
```
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
python3 info_gathering.py -d example.com
```

Override the IP used for Shodan/Geolocation
```
python3 info_gathering.py -d example.com -s 93.184.216.34
```

## 📂 Example Output

Example console summary:
```
[+] Getting whois information...
[+] Whois: found keys: domain_name, registrar, creation_date, expiration_date
[+] Getting DNS information...
[+] A records: ['93.184.216.34']
[+] MX records: none
[+] NS records: ['a.iana-servers.net', 'b.iana-servers.net']
[+] TXT records: none
[+] Using first A record for IP-based lookups: 93.184.216.34
[+] Getting geolocation information...
[+] Geolocation: {'country_name': 'United States', 'city': 'Los Angeles', 'latitude': 34.05, 'longitude': -118.24}
[+] Getting Shodan information for 93.184.216.34 ...
[+] Shodan: org: ExampleOrg os: Linux
[+] Shodan: open ports: [80, 443]
```

## ⚖️ License

This project is licensed under the MIT License
.

## 🛡 Disclaimer

This tool is for educational purposes and authorized penetration testing only.
Using it on systems without permission may be illegal. The authors are not responsible for misuse.



