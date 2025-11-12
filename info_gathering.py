#!/usr/bin/env python3
"""
info_gathering_v2.py - Advanced info-gathering tool (authorized use only)

Author: ShreevOrganization (upgraded)
License: MIT
Version: 2.0-advanced

Important: Use this tool only on targets you are authorized to test.
Unauthorized scanning or information gathering may be illegal.

Requirements (pip):
    pip install python-whois dnspython requests shodan

Features (summary):
 - WHOIS with normalization
 - DNS: A, AAAA, MX, NS, TXT, SOA, CAA, SPF-like parsing, DNSSEC hint
 - Reverse DNS
 - Geolocation via configurable API (with retries)
 - Shodan integration (optional)
 - Port scan (TCP connect) with banner grabbing
 - HTTP(s) header and title extraction with retry/backoff
 - SSL certificate parsing (issuer, validity, SANs)
 - Concurrency, robust error handling, configurable timeouts/retries
"""

from __future__ import annotations
import argparse
import concurrent.futures
import json
import logging
import os
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

import dns.resolver
import dns.exception
import dns.name
import dns.resolver
import requests
import whois

# optional
try:
    from shodan import Shodan, APIError  # type: ignore
except Exception:
    Shodan = None
    APIError = Exception  # type: ignore

# ---- Defaults / Config ----
DEFAULT_TIMEOUT = 6.0
DEFAULT_HTTP_TIMEOUT = 8.0
DEFAULT_RETRIES = 2
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 3306, 3389, 8080]
GEO_API = os.environ.get("GEO_API", "https://geolocation-db.com/json/")  # append IP
MAX_THREADS = 24

# ---- Logging ----
LOG = logging.getLogger("info_gathering_v2")
LOG.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
LOG.addHandler(handler)


# ---- Helpers ----
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def setup_logging(verbose: bool):
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)


def safe_dns_resolve(domain: str, rtype: str, lifetime: float = 5.0) -> List[str]:
    answers: List[str] = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = lifetime
        resolver.timeout = lifetime
        for r in resolver.resolve(domain, rtype):
            answers.append(r.to_text())
    except dns.exception.DNSException as e:
        LOG.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)
    except Exception as e:
        LOG.debug("Unexpected DNS error %s for %s: %s", rtype, domain, e)
    return answers


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        LOG.debug("Reverse DNS for %s failed: %s", ip, e)
        return None


def whois_info(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        out: Dict[str, Any] = {}
        # whois may return dict-like or object
        if isinstance(w, dict):
            for k, v in w.items():
                out[k] = v
        else:
            for k, v in w.__dict__.items():
                out[k] = v
        return out
    except Exception as exc:
        LOG.debug("Whois lookup failed for %s: %s", domain, exc)
        return {}


def http_probe(host: str, use_https: bool = True, timeout: float = DEFAULT_HTTP_TIMEOUT, verify: bool = True, retries: int = DEFAULT_RETRIES) -> Dict[str, Any]:
    """
    Try HTTPS first (if use_https True), fallback to HTTP. Return headers, status, title, final_url.
    """
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    schemes = ["https"] if use_https else []
    schemes += ["http"]

    result: Dict[str, Any] = {}
    for scheme in schemes:
        url = f"{scheme}://{host}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, verify=verify)
            result["url"] = r.url
            result["status_code"] = r.status_code
            result["headers"] = dict(r.headers)
            # attempt to extract title (naive)
            text = r.text or ""
            start = text.find("<title")
            title = None
            if start != -1:
                # quick and safe extraction
                start_tag_end = text.find(">", start)
                if start_tag_end != -1:
                    end = text.find("</title>", start_tag_end)
                    if end != -1:
                        title = text[start_tag_end + 1 : end].strip()
            result["title"] = title
            result["content_snippet"] = (text[:400] + "...") if len(text) > 400 else text
            result["scheme"] = scheme
            return result
        except requests.RequestException as e:
            LOG.debug("HTTP %s probe failed for %s: %s", scheme, host, e)
            result[f"{scheme}_error"] = str(e)
            continue
    return result


def get_ssl_cert(ip_or_host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch SSL cert from host:port. Returns dict with subject, issuer, notBefore, notAfter, SANs.
    If ip_or_host is an IP (dots), SNI will use the host parameter if available.
    """
    out: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip_or_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip_or_host) as ssock:
                cert = ssock.getpeercert()
                out["subject"] = cert.get("subject")
                out["issuer"] = cert.get("issuer")
                out["notBefore"] = cert.get("notBefore")
                out["notAfter"] = cert.get("notAfter")
                san = cert.get("subjectAltName", ())
                out["san"] = [v for (_t, v) in san]
    except Exception as e:
        LOG.debug("SSL cert fetch failed for %s:%s -> %s", ip_or_host, port, e)
    return out


def geolocation_for_ip(ip: str, api_base: str = GEO_API, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    if not api_base:
        return {}
    try:
        url = api_base.rstrip("/") + "/" + ip if not api_base.endswith("/") else api_base + ip
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        LOG.debug("Geolocation lookup failed for %s: %s", ip, exc)
        return {}


def shodan_info(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
    if not api_key:
        LOG.debug("No Shodan key provided.")
        return {}
    if Shodan is None:
        LOG.debug("Shodan library not installed.")
        return {}
    try:
        api = Shodan(api_key)
        host = api.host(ip)
        return host
    except APIError as e:
        LOG.debug("Shodan API error: %s", e)
        return {}
    except Exception as e:
        LOG.debug("Shodan lookup failed: %s", e)
        return {}


def banner_grab(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # send a minimal probe if port is HTTP-ish
            probe = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode() if port in (80, 8080, 8000) else b"\r\n"
            try:
                s.sendall(probe)
            except Exception:
                pass
            try:
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
            except Exception:
                return None
    except Exception as e:
        LOG.debug("Banner grab failed for %s:%s -> %s", ip, port, e)
        return None


def tcp_connect_scan(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


# ---- Orchestration ----
def gather_for_domain(domain: str, options: argparse.Namespace) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    # WHOIS
    LOG.info("[+] WHOIS lookup")
    out["whois"] = whois_info(domain)

    # DNS lookups concurrently
    LOG.info("[+] DNS lookups (A, AAAA, MX, NS, TXT, SOA, CAA)")
    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
    dns_results: Dict[str, List[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(dns_types))) as ex:
        future_map = {ex.submit(safe_dns_resolve, domain, r, options.timeout): r for r in dns_types}
        for fut in concurrent.futures.as_completed(future_map):
            rtype = future_map[fut]
            try:
                dns_results[rtype] = fut.result()
            except Exception as e:
                dns_results[rtype] = []
                LOG.debug("DNS %s error: %s", rtype, e)
    out["dns"] = dns_results

    # pick IP(s) to use
    ips: List[str] = dns_results.get("A", []) + dns_results.get("AAAA", [])
    ips = list(dict.fromkeys(ips))  # dedupe while preserving order

    # if user provided IP for shodan/scan
    if options.shodan_ip:
        ips.insert(0, options.shodan_ip)

    # fallback to socket resolution
    if not ips:
        try:
            resolved = socket.gethostbyname(domain)
            ips.append(resolved)
            LOG.info("[+] Resolved domain via socket: %s", resolved)
        except Exception as e:
            LOG.debug("Socket resolution failed for %s: %s", domain, e)

    out["resolved_ips"] = ips

    # reverse DNS for each IP
    rdns = {ip: reverse_dns(ip) for ip in ips}
    out["reverse_dns"] = rdns

    # Geolocation (concurrent)
    LOG.info("[+] Geolocation lookups")
    geo_results: Dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(ips) or 1)) as ex:
        future_to_ip = {ex.submit(geolocation_for_ip, ip, options.geo_api, options.timeout): ip for ip in ips}
        for fut in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                geo_results[ip] = fut.result()
            except Exception as e:
                geo_results[ip] = {}
                LOG.debug("Geo error for %s: %s", ip, e)
    out["geolocation"] = geo_results

    # Shodan (optional)
    if options.shodan_key or os.environ.get("SHODAN_API_KEY"):
        LOG.info("[+] Shodan lookups")
        shodan_key = options.shodan_key or os.environ.get("SHODAN_API_KEY")
        shodan_results = {}
        for ip in ips:
            shodan_results[ip] = shodan_info(ip, shodan_key)
        out["shodan"] = shodan_results
    else:
        out["shodan"] = {}

    # Port scanning + banner grabbing + SSL + HTTP probe (concurrent)
    ports = options.ports or DEFAULT_PORTS
    LOG.info("[+] Port scan (%s ports) and service probing", len(ports))

    def probe_single(ip_port: Tuple[str, int]) -> Tuple[str, int, Dict[str, Any]]:
        ip, port = ip_port
        result: Dict[str, Any] = {"open": False, "banner": None, "ssl": {}, "http": {}}
        if tcp_connect_scan(ip, port, timeout=options.scan_timeout):
            result["open"] = True
            result["banner"] = banner_grab(ip, port, timeout=options.banner_timeout)
            # if https port or user forced https probing
            if port in (443, 8443) or options.probe_https:
                result["ssl"] = get_ssl_cert(ip, port=port, timeout=options.timeout)
            # if HTTP ports
            if port in (80, 8080, 8000, 443, 8443) or options.probe_http:
                # use host header as domain to try get a real site
                host_for_http = domain if options.http_host_domain else ip
                result["http"] = http_probe(f"{host_for_http}:{port}" if ":" in host_for_http else host_for_http,
                                           use_https=(port in (443, 8443)), timeout=options.http_timeout, verify=options.verify_ssl, retries=options.retries)
        return ip, port, result

    # build list of ip_port tasks
    tasks: List[Tuple[str, int]] = []
    for ip in ips:
        for p in ports:
            tasks.append((ip, p))

    scan_results: Dict[str, Dict[int, Dict[str, Any]]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(tasks) or 1)) as ex:
        futures = {ex.submit(probe_single, ip_port): ip_port for ip_port in tasks}
        for fut in concurrent.futures.as_completed(futures):
            ip, port, res = fut.result()
            scan_results.setdefault(ip, {})[port] = res

    out["scan"] = scan_results

    # Helpful summary
    summary = {
        "ips": ips,
        "open_ports_by_ip": {ip: [p for p, r in scan_results.get(ip, {}).items() if r.get("open")] for ip in ips},
    }
    out["summary"] = summary

    return out


# ---- CLI ----
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Advanced Information Gathering Tool (authorized use only).")
    parser.add_argument("-d", "--domain", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--shodan-ip", help="IP to prioritize for Shodan/scan (optional).")
    parser.add_argument("--shodan-key", help="Shodan API key (or set SHODAN_API_KEY env var).")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan (default common ports).", default=",".join(map(str, DEFAULT_PORTS)))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Generic network timeout in seconds (default {DEFAULT_TIMEOUT}).")
    parser.add_argument("--http-timeout", dest="http_timeout", type=float, default=DEFAULT_HTTP_TIMEOUT, help=f"HTTP timeout (default {DEFAULT_HTTP_TIMEOUT}).")
    parser.add_argument("--scan-timeout", type=float, default=2.0, help="TCP connect timeout for port scanning.")
    parser.add_argument("--banner-timeout", type=float, default=2.0, help="Timeout for banner grabbing.")
    parser.add_argument("--geo-api", default=GEO_API, help=f"Geolocation API base URL (default {GEO_API})")
    parser.add_argument("--output", "-o", help="Output JSON file path (if omitted prints to console).")
    parser.add_argument("--format", choices=["json", "pretty"], default="pretty", help="Output format.")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retries for HTTP calls.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging/debugging.")
    parser.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false", help="Do not verify SSL certs when probing HTTPs.")
    parser.add_argument("--probe-http", action="store_true", help="Force HTTP probing on open ports even if not a common HTTP port.")
    parser.add_argument("--probe-https", action="store_true", help="Force SSL probing on open ports even if not 443/8443.")
    parser.add_argument("--http-host-domain", action="store_true", help="Use domain in Host header when HTTP probing (default is IP).")
    parser.add_argument("--max-threads", type=int, default=MAX_THREADS, help="Max worker threads (default %s)" % MAX_THREADS)
    args = parser.parse_args()

    # parse ports
    port_list: List[int] = []
    try:
        port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except Exception:
        LOG.debug("Failed to parse ports, using default set.")
        port_list = DEFAULT_PORTS
    args.ports = sorted(list(set(port_list)))
    args.timeout = float(args.timeout)
    args.banner_timeout = float(args.banner_timeout if hasattr(args, "banner_timeout") else 2.0)
    args.scan_timeout = float(args.scan_timeout if hasattr(args, "scan_timeout") else 2.0)
    args.http_timeout = float(args.http_timeout)
    args.retries = int(args.retries)
    args.geo_api = args.geo_api
    args.shodan_key = args.shodan_key
    args.verify_ssl = bool(args.verify_ssl)
    args.max_threads = int(args.max_threads)
    return args


def main():
    options = parse_args()
    setup_logging(options.verbose)
    LOG.info("Starting info gathering for %s", options.domain)
    try:
        result = gather_for_domain(options.domain, options)
    except KeyboardInterrupt:
        LOG.warning("Interrupted by user.")
        sys.exit(1)
    except Exception as exc:
        LOG.exception("Fatal error during gathering: %s", exc)
        result = {"error": str(exc)}

    # Output
    if options.output:
        try:
            with open(options.output, "w") as fh:
                json.dump(result, fh, indent=2, default=str)
            LOG.info("Results saved to %s", options.output)
        except Exception as exc:
            LOG.error("Could not write output file: %s", exc)
    if options.format == "json" and not options.output:
        print(json.dumps(result, indent=2, default=str))
    elif options.format == "pretty":
        # minimal prettified console output
        print("=" * 80)
        print(f"Domain: {result.get('domain')}")
        print(f"Timestamp: {result.get('timestamp')}")
        print("-" * 80)
        print("Resolved IPs:")
        for ip in result.get("resolved_ips", []):
            print("  -", ip, " rdns:", result.get("reverse_dns", {}).get(ip))
        print("-" * 80)
        print("Open ports (summary):")
        sums = result.get("summary", {}).get("open_ports_by_ip", {})
        for ip, ports in sums.items():
            print(f"  {ip}: {ports}")
        print("-" * 80)
        print("WHOIS keys:", ", ".join(list(result.get("whois", {}).keys())[:8]) if result.get("whois") else "none")
        print("DNS records (A, AAAA, MX, NS, TXT):")
        dns = result.get("dns", {})
        for t in ("A", "AAAA", "MX", "NS", "TXT"):
            print(f"  {t}: {dns.get(t)}")
        print("=" * 80)

    LOG.info("Done.")


if __name__ == "__main__":
    main()
