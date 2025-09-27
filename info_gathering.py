#!/usr/bin/env python3
"""
info_gathering.py - Simple info-gathering tool (authorized use only)

Author: Dhruv Bhoir

License: MIT

Version: 2.0

Usage:
  python3 info_gathering.py -d example.com
  python3 info_gathering.py -d example.com -s 1.2.3.4 --output result.json

Requirements:
  pip install python-whois dnspython requests shodan
"""

import argparse
import json
import os
import socket
import sys
import time
from typing import Optional

import dns.resolver
import requests
import whois
from shodan import Shodan, APIError

# ---- Config ----
REQUEST_TIMEOUT = 6  # seconds for HTTP calls
GEO_API = "https://geolocation-db.com/json/"  # appended with IP

# ---- Helpers ----


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def safe_resolve_a(domain: str):
    answers = []
    try:
        for r in dns.resolver.resolve(domain, "A"):
            answers.append(r.to_text())
    except Exception as e:
        eprint(f"[-] A record lookup failed: {e}")
    return answers

# generic DNS resolver with error handling

def safe_resolve(domain: str, record_type: str):
    res = []
    try:
        for r in dns.resolver.resolve(domain, record_type, lifetime=5):
            res.append(r.to_text())
    except Exception as e:
        # not all domains have every record type; don't spam
        eprint(f"[-] {record_type} lookup: {e}")
    return res

# Whois lookup with error handling

def whois_info(domain: str):
    try:
        w = whois.whois(domain)
        # whois.whois returns dict-like object; convert to normal dict with simple types
        out = {}
        for k, v in w.items() if isinstance(w, dict) else w.__dict__.items():
            out[k] = v
        return out
    except Exception as exc:
        eprint(f"[-] Whois lookup failed: {exc}")
        return {}

# Geolocation lookup with error handling
def geolocation_for_ip(ip: str):
    try:
        url = GEO_API + ip
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        eprint(f"[-] Geolocation lookup failed: {exc}")
        return {}


def shodan_info_for_ip(ip: str, api_key: Optional[str]):
    if not api_key:
        eprint("[-] No Shodan API key provided (set SHODAN_API_KEY env or use -k). Skipping Shodan.")
        return {}

    api = Shodan(api_key)
    try:
        host = api.host(ip)
        return host
    except APIError as e:
        eprint(f"[-] Shodan API error: {e}")
        return {}
    except Exception as e:
        eprint(f"[-] Shodan lookup failed: {e}")
        return {}


# ---- Main ----
def main():
    parser = argparse.ArgumentParser(description="Information Gathering Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument(
        "-s",
        "--shodan",
        help="Optional IP address to query Shodan for (if omitted, will use resolved A record IP)",
    )
    parser.add_argument(
        "-k",
        "--shodan-key",
        help="Shodan API key. If omitted, will read from env var SHODAN_API_KEY",
    )
    parser.add_argument(
        "-o", "--output", help="Optional JSON output file to save results", default=None
    )
    args = parser.parse_args()

    domain = args.domain.strip()
    shodan_ip_arg = args.shodan
    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")

    results = {"domain": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # ---- Whois ----
    print("[+] Getting whois information...")
    results["whois"] = whois_info(domain)
    if results["whois"]:
        print("[+] Whois: found keys:", ", ".join(list(results["whois"].keys())[:8]))
    else:
        print("[-] Whois: no data")

    # ---- DNS ----
    # generic DNS resolver with error handling
    print("[+] Getting DNS information...")
    a_records = safe_resolve_a(domain)
    results["dns"] = {
        "A": a_records,
        "MX": safe_resolve(domain, "MX"),
        "NS": safe_resolve(domain, "NS"),
        "TXT": safe_resolve(domain, "TXT"),
    }
    for t, vals in results["dns"].items():
        print(f"[+] {t} records: {vals if vals else 'none'}")

    # determine IP for geolocation / shodan 
    ip_for_lookups = shodan_ip_arg
    if not ip_for_lookups:
        if a_records:
            ip_for_lookups = a_records[0]
            print(f"[+] Using first A record for IP-based lookups: {ip_for_lookups}")
        else:
            try:
                ip_for_lookups = socket.gethostbyname(domain)
                print(f"[+] Resolved domain to IP via socket: {ip_for_lookups}")
            except Exception as e:
                eprint(f"[-] Could not resolve IP for domain: {e}")

    # ---- Geolocation ----
    if ip_for_lookups:
        print("[+] Getting geolocation information...")
        geo = geolocation_for_ip(ip_for_lookups)
        results["geolocation"] = geo
        if geo:
            pretty_geo = {k: geo.get(k) for k in ("country_name", "city", "state", "latitude", "longitude") if k in geo}
            print("[+] Geolocation:", pretty_geo)
    else:
        results["geolocation"] = {}
        eprint("[-] No IP available for geolocation lookup.")

    # ---- Shodan ----
    if ip_for_lookups:
        print(f"[+] Getting Shodan information for {ip_for_lookups} ...")
        shodan_data = shodan_info_for_ip(ip_for_lookups, shodan_key)
        results["shodan"] = shodan_data
        if shodan_data:
            # print a few useful fields
            print("[+] Shodan: org:", shodan_data.get("org"), "os:", shodan_data.get("os"))
            print("[+] Shodan: open ports:", shodan_data.get("ports"))
        else:
            print("[-] Shodan: no data or error")
    else:
        results["shodan"] = {}

    # ---- Output ----
    if args.output:
        try:
            with open(args.output, "w") as fh:
                json.dump(results, fh, indent=2, default=str)
            print(f"[+] Results saved to {args.output}")
        except Exception as exc:
            eprint(f"[-] Could not write output file: {exc}")
    else:
        # pretty print to console
        print("\n--- Full JSON Result ---")
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()

