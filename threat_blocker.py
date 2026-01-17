#!/usr/bin/env python3
import requests
import json
import sys
import subprocess
from datetime import datetime
import config
import time

BLOCK_THRESHOLD = 80
LOG_FILE = "enrichment.log"
BLOCKED_LOG = "blocked_ips.log"

def log_enrichment(data):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {json.dumps(data, indent=2)}\n\n")

def log_blocked(ip, reason):
    with open(BLOCKED_LOG, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] BLOCKED {ip} - {reason}\n")

def block_ip_iptables(ip):
    try:
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True)
        print(f"[+] BLOCKED {ip} via iptables")
        log_blocked(ip, "AbuseIPDB score >= 80")
        return True
    except Exception as e:
        print(f"[-] Failed to block {ip}: {e}")
        return False

def enrich_ip(ip):
    result = {"ip": ip, "sources": {}, "blocked": False}

    # AbuseIPDB
    try:
        headers = {'Key': config.ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers=headers,
            timeout=10
        )
        data = r.json().get("data", {})
        result["sources"]["abuseipdb"] = {
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0)
        }
    except:
        result["sources"]["abuseipdb"] = {"error": "failed"}

    # IPinfo
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json?token={config.IPINFO_TOKEN}", timeout=10)
        result["sources"]["ipinfo"] = r.json()
    except:
        result["sources"]["ipinfo"] = {"error": "failed"}

    # Shodan
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            result["sources"]["shodan"] = {
                "ports": len(d.get("ports", [])),
                "tags": d.get("tags", [])
            }
        else:
            result["sources"]["shodan"] = {"error": "not found"}
    except:
        result["sources"]["shodan"] = {"error": "failed"}

    score = result["sources"]["abuseipdb"].get("score", 0)
    if score >= BLOCK_THRESHOLD:
        block_ip_iptables(ip)
        result["blocked"] = True

    log_enrichment(result)
    return result

def print_result(data):
    print("\n" + "="*70)
    print(f"THREAT ENRICHMENT + BLOCKING: {data['ip']}")
    print("="*70)

    score = data["sources"]["abuseipdb"].get("score", 0)
    status = "BLOCKED" if data["blocked"] else "MONITOR"
    print(f"[ABUSEIPDB] Score: {score}% → {status}")

    info = data["sources"].get("ipinfo", {})
    if "error" not in info:
        print(f"[IPINFO] {info.get('city', 'N/A')}, {info.get('country', 'N/A')} | {info.get('org', 'N/A')}")

    shodan = data["sources"].get("shodan", {})
    if "error" not in shodan:
        print(f"[SHODAN] Open ports: {shodan.get('ports', 0)}")

    print("="*70 + "\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./threat_blocker.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]
    result = enrich_ip(ip)
    print_result(result)
