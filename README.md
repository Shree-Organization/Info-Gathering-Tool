<h1 align="center">🔎 Info Gathering Tool</h1>

<p align="center">
  <b>Advanced domain and IP reconnaissance tool for ethical OSINT and cybersecurity analysis</b>  
  <br>
  Built with <code>Python</code> • <code>dnspython</code> • <code>requests</code> • <code>whois</code> • <code>Shodan</code>
</p>

<p align="center">
  <a href="https://github.com/Shree-Organization/Info-Gathering-Tool/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Shree-Organization/Info-Gathering-Tool/ci.yml?label=CI%2FCD&logo=github" alt="CI/CD" />
  </a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python 3.9+" />
  <a href="https://github.com/Shree-Organization/Info-Gathering-Tool/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" />
  </a>
  <img src="https://img.shields.io/badge/Docker-ready-blue.svg" alt="Docker ready" />
  <img src="https://img.shields.io/badge/tests-passing-brightgreen.svg" alt="Tests passing" />
  <br><br>
  <a href="https://github.com/Shree-Organization/Info-Gathering-Tool/stargazers">
    <img src="https://img.shields.io/github/stars/Shree-Organization/Info-Gathering-Tool?style=social" alt="GitHub stars" />
  </a>
  <a href="https://github.com/Shree-Organization/Info-Gathering-Tool/network/members">
    <img src="https://img.shields.io/github/forks/Shree-Organization/Info-Gathering-Tool?style=social" alt="GitHub forks" />
  </a>
</p>

---

> ⚠️ **For educational and authorized security testing only.** Do **not** use this tool against systems you do not have permission to test.

---

## 🚀 Features

* 🌐 **WHOIS Lookup** — Domain registration details
* 🧭 **DNS Records** — A, MX, NS, TXT, and more
* 📍 **Geolocation** — Locate IP origin via public APIs
* 🔍 **Shodan Integration** — Fetch open ports, OS, and services
* 💾 **JSON Output** — Save complete structured data
* 🧱 **Error Handling** — Gracefully continues on failures
* 🔑 **Shodan API Key** — Passed via CLI or environment variable

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Shree-Organization/Info-Gathering-Tool.git
cd info-gathering-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🛠 Usage

### Basic Example

```bash
python3 info_gathering.py -d example.com
```

### Save Results to JSON

```bash
python3 info_gathering.py -d example.com -o results.json
```

### With Shodan API Key

```bash
python3 info_gathering.py -d example.com -k YOUR_SHODAN_KEY
```

Or set environment variable:

```bash
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
python3 info_gathering.py -d example.com
```

### Specify IP for Geolocation/Shodan

```bash
python3 info_gathering.py -d example.com -s 93.184.216.34
```

---

## 📊 Example Output

```bash
[+] Getting whois information...
[+] Whois: found keys: domain_name, registrar, creation_date, expiration_date
[+] Getting DNS information...
[+] A records: ['93.184.216.34']
[+] MX records: none
[+] NS records: ['a.iana-servers.net', 'b.iana-servers.net']
[+] TXT records: none
[+] Using first A record for IP-based lookups: 93.184.216.34
[+] Getting geolocation information...
[+] Geolocation: {"country_name": "United States", "city": "Los Angeles", "latitude": 34.05, "longitude": -118.24}
[+] Getting Shodan information for 93.184.216.34 ...
[+] Shodan: org: ExampleOrg os: Linux
[+] Shodan: open ports: [80, 443]
```

---

## 🧰 Project Structure

```
info-gathering-tool/
├── info_gathering.py
├── requirements.txt
├── README.md
├── LICENSE
└── results/
```

---

## 🧱 Dependencies

| Package        | Purpose                 |
| -------------- | ----------------------- |
| `requests`     | HTTP requests for APIs  |
| `dnspython`    | DNS record resolution   |
| `python-whois` | Domain WHOIS data       |
| `shodan`       | Shodan API integration  |
| `certifi`      | Secure SSL certificates |

---

## 🧩 Future Enhancements

* [ ] Add asynchronous lookups for speed
* [ ] Integrate subdomain enumeration
* [ ] Add banner grabbing & WAF detection
* [ ] Create Flask-based web dashboard

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE).

---

## 🛡 Disclaimer

This tool is for **educational purposes and authorized testing only**.
Misuse against unauthorized systems may violate applicable laws.
The authors are **not responsible** for any misuse or damage.

---

## 👨‍💻 Maintainers

* **Author:** ShreevOrganization
* **Maintained by:** [Shree Organization](https://www.linkedin.com/company/shree-org/)
  ✉️ [organizationshree@gmail.com](mailto:organizationshree@gmail.com)
  🔗 [GitHub – Shree-Organization](https://github.com/Shree-Organization)

---

<p align="center">If you find this project useful, please ⭐ star the repository and share it!</p>
<p align="center"><sub>Built with ❤️ by <b>CodeM03</b> — Empowering ethical cybersecurity 🕵️‍♂️</sub></p>


