[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Threat-intel-auto-blocker
Automated Python SOC tool: Enriches IP with AbuseIPDB, IPinfo &amp; Shodan. Blocks malicious IPs (score ≥80%) via iptables. Full logging &amp; CLI usage. SOC analyst project.

---

# Threat-Intel-Auto-Blocker

Automated Python SOC tool that enriches IP addresses with threat intelligence from AbuseIPDB, IPinfo, and Shodan. If Abuse Confidence Score ≥ 80%, it automatically blocks the IP via iptables. Includes full logging and CLI usage.

## Features
- IP enrichment (reputation, geolocation, open ports)
- Auto-block malicious IPs on Linux firewall (iptables)
- Logs enrichment results and blocked IPs
- Simple CLI: `./threat_blocker.py <IP>`

## Requirements
- Python 3
- Linux (for iptables)
- API keys from:
  - AbuseIPDB
  - IPinfo
  - Shodan

## Setup
1. Clone or download the repo
2. Create virtual environment:
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install requests
   ```
3. Create `config.py` with your keys (never commit this file!):
   ```python
   ABUSEIPDB_API_KEY = "your_key"
   IPINFO_TOKEN = "your_token"
   SHODAN_API_KEY = "your_key"
   ```
4. Make script executable:
   ```
   chmod +x threat_blocker.py
   ```

## Usage
```
./threat_blocker.py 8.8.8.8
./threat_blocker.py 104.234.140.98   # will block if score high
```

## Notes
- Run with sudo privileges for iptables blocking
- Test with high-score IPs from abuseipdb.com
- For production: integrate with Splunk/IDS alerts

SOC analyst project – detection → enrichment → automated response.

## License
MIT License – see [LICENSE](LICENSE) file.
