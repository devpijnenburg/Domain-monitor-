#!/usr/bin/env python3
"""Domain checker — runs internet.nl-style checks on a list of domains."""
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
import checkdmarc

DOMAINS_FILE = os.getenv("DOMAINS_FILE", "/data/domains.txt")
RESULTS_FILE = os.getenv("RESULTS_FILE", "/data/results.json")
TRIGGER_FILE = "/data/scan.trigger"
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL_HOURS", "24")) * 3600

CHECK_WEIGHTS = {
    "https":    20,
    "tls_cert": 20,
    "hsts":     10,
    "ipv6":     10,
    "dnssec":   15,
    "spf":      10,
    "dmarc":    15,
}


def check_https(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        return {"status": "passed", "detail": f"HTTP {r.status_code}"}
    except requests.exceptions.SSLError as e:
        return {"status": "failed", "detail": f"SSL fout: {str(e)[:80]}"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_tls_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            return {"status": "failed", "detail": "Certificaat verlopen"}
        if days < 14:
            return {"status": "warning", "detail": f"Verloopt over {days} dagen"}
        return {"status": "passed", "detail": f"Geldig, nog {days} dagen"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_hsts(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=False)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if not hsts:
            return {"status": "failed", "detail": "HSTS header ontbreekt"}
        if "max-age" in hsts:
            return {"status": "passed", "detail": hsts[:80]}
        return {"status": "warning", "detail": f"HSTS incompleet: {hsts[:60]}"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_ipv6(domain):
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if results:
            return {"status": "passed", "detail": results[0][4][0]}
        return {"status": "failed", "detail": "Geen AAAA record"}
    except socket.gaierror:
        return {"status": "failed", "detail": "Geen AAAA record"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_dnssec(domain):
    try:
        ds = dns.resolver.resolve(domain, "DS", raise_on_no_answer=False)
        if ds.rrset:
            return {"status": "passed", "detail": "DS record aanwezig"}
        dnskey = dns.resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if dnskey.rrset:
            return {"status": "warning", "detail": "DNSKEY aanwezig maar geen DS"}
        return {"status": "failed", "detail": "Geen DNSSEC records"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_spf(domain):
    try:
        result = checkdmarc.check_spf(domain)
        if result.get("valid"):
            return {"status": "passed", "detail": (result.get("record") or "")[:80]}
        return {"status": "failed", "detail": (result.get("error") or "Geen geldig SPF record")[:80]}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def check_dmarc(domain):
    try:
        result = checkdmarc.check_dmarc(domain)
        if result.get("valid"):
            policy = (result.get("tags") or {}).get("p", {}).get("value", "?")
            return {"status": "passed", "detail": f"policy={policy}"}
        return {"status": "failed", "detail": (result.get("error") or "Geen DMARC record")[:80]}
    except Exception as e:
        return {"status": "failed", "detail": str(e)[:80]}


def compute_score(checks):
    total = sum(CHECK_WEIGHTS.values())
    earned = sum(w for k, w in CHECK_WEIGHTS.items() if checks.get(k, {}).get("status") == "passed")
    earned += sum(w / 2 for k, w in CHECK_WEIGHTS.items() if checks.get(k, {}).get("status") == "warning")
    return round(earned / total * 100)


def scan_domain(domain):
    print(f"  {domain} ...", flush=True)
    checks = {
        "https":    check_https(domain),
        "tls_cert": check_tls_cert(domain),
        "hsts":     check_hsts(domain),
        "ipv6":     check_ipv6(domain),
        "dnssec":   check_dnssec(domain),
        "spf":      check_spf(domain),
        "dmarc":    check_dmarc(domain),
    }
    score = compute_score(checks)
    print(f"    → score {score}%", flush=True)
    return {"checks": checks, "total_score": score}


def load_domains():
    p = Path(DOMAINS_FILE)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]


def run_scan():
    domains = load_domains()
    if not domains:
        print(f"Geen domeinen gevonden in {DOMAINS_FILE}", flush=True)
        return

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] Scannen van {len(domains)} domein(en)...", flush=True)
    results = {}
    for domain in domains:
        try:
            results[domain] = scan_domain(domain)
        except Exception as e:
            print(f"  FOUT bij {domain}: {e}", flush=True)
            results[domain] = {"checks": {}, "total_score": None}

    output = {"scan_date": datetime.now(timezone.utc).isoformat(), "results": results}
    Path(RESULTS_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(RESULTS_FILE).write_text(json.dumps(output, indent=2))
    print(f"Resultaten opgeslagen in {RESULTS_FILE}", flush=True)


def wait_for_next_scan(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if Path(TRIGGER_FILE).exists():
            try:
                Path(TRIGGER_FILE).unlink()
            except OSError:
                pass
            print("Handmatige scan getriggerd.", flush=True)
            return
        time.sleep(10)


if __name__ == "__main__":
    while True:
        run_scan()
        print(f"Volgende scan over {SCAN_INTERVAL // 3600} uur.", flush=True)
        wait_for_next_scan(SCAN_INTERVAL)
