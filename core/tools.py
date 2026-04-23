"""
core/tools.py
API wrappers for the three threat intel sources.
Each function returns a normalised dict so the agent works
with a consistent structure regardless of which API was called.

All functions gracefully degrade — if an API key is missing or
the request fails, they return a structured error dict rather
than raising an exception. The agent can handle partial data.
"""

import os
import socket
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
REQUEST_TIMEOUT = 10  # seconds


# ── VirusTotal ─────────────────────────────────────────────────────────────

def lookup_virustotal(target: str) -> dict:
    """
    Query VirusTotal for reputation data on an IP or domain.
    Returns a normalised dict with malicious/suspicious/clean counts.
    """
    if not VT_API_KEY:
        return _mock_virustotal(target)

    headers = {"x-apikey": VT_API_KEY}

    # Determine endpoint — IP vs domain
    try:
        import ipaddress
        ipaddress.ip_address(target)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    except ValueError:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "source":     "virustotal",
                "target":     target,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean":      stats.get("harmless", 0) + stats.get("undetected", 0),
                "total":      sum(stats.values()),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                "error":      None,
            }
        elif response.status_code == 404:
            return _not_found("virustotal", target)
        else:
            return _api_error("virustotal", target, f"HTTP {response.status_code}")
    except requests.RequestException as e:
        return _api_error("virustotal", target, str(e))


def _mock_virustotal(target: str) -> dict:
    """Mock response when no API key is set — useful for testing."""
    mock_data = {
        "8.8.8.8":        {"malicious": 0,  "suspicious": 0,  "clean": 88, "reputation": 100},
        "1.1.1.1":        {"malicious": 0,  "suspicious": 0,  "clean": 85, "reputation": 98},
        "malware.com":    {"malicious": 45, "suspicious": 8,  "clean": 3,  "reputation": -85},
        "phishing.net":   {"malicious": 32, "suspicious": 12, "clean": 10, "reputation": -70},
        "suspicious.io":  {"malicious": 5,  "suspicious": 15, "clean": 50, "reputation": -20},
    }
    data = mock_data.get(target, {"malicious": 0, "suspicious": 2, "clean": 70, "reputation": 0})
    return {
        "source":     "virustotal",
        "target":     target,
        "malicious":  data["malicious"],
        "suspicious": data["suspicious"],
        "clean":      data["clean"],
        "total":      data["malicious"] + data["suspicious"] + data["clean"],
        "reputation": data["reputation"],
        "error":      None,
        "mock":       True,
    }


# ── AbuseIPDB ──────────────────────────────────────────────────────────────

def lookup_abuseipdb(target: str) -> dict:
    """
    Query AbuseIPDB for abuse confidence score on an IP.
    Returns a normalised dict. Domain targets get a graceful skip
    since AbuseIPDB is IP-only.
    """
    # AbuseIPDB only handles IPs
    try:
        import ipaddress
        ipaddress.ip_address(target)
    except ValueError:
        return {
            "source":           "abuseipdb",
            "target":           target,
            "skipped":          True,
            "skip_reason":      "AbuseIPDB only supports IP addresses, not domains",
            "error":            None,
        }

    if not ABUSEIPDB_KEY:
        return _mock_abuseipdb(target)

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": target, "maxAgeInDays": 90, "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source":              "abuseipdb",
                "target":              target,
                "abuse_score":         data.get("abuseConfidenceScore", 0),
                "total_reports":       data.get("totalReports", 0),
                "country":             data.get("countryCode", "unknown"),
                "isp":                 data.get("isp", "unknown"),
                "domain":              data.get("domain", ""),
                "is_tor":              data.get("isTor", False),
                "is_public":           data.get("isPublic", True),
                "last_reported":       data.get("lastReportedAt", "never"),
                "error":               None,
            }
        else:
            return _api_error("abuseipdb", target, f"HTTP {response.status_code}")
    except requests.RequestException as e:
        return _api_error("abuseipdb", target, str(e))


def _mock_abuseipdb(target: str) -> dict:
    """Mock response when no API key is set."""
    mock_data = {
        "8.8.8.8":      {"abuse_score": 0,  "total_reports": 0,   "country": "US", "isp": "Google LLC",     "is_tor": False},
        "1.1.1.1":      {"abuse_score": 0,  "total_reports": 2,   "country": "AU", "isp": "Cloudflare Inc", "is_tor": False},
        "185.220.101.1":{"abuse_score": 98, "total_reports": 842,  "country": "DE", "isp": "Tor Exit Node",  "is_tor": True},
        "192.0.2.1":    {"abuse_score": 45, "total_reports": 156,  "country": "RU", "isp": "Unknown ISP",    "is_tor": False},
    }
    data = mock_data.get(target, {"abuse_score": 10, "total_reports": 5, "country": "unknown", "isp": "unknown", "is_tor": False})
    return {
        "source":        "abuseipdb",
        "target":        target,
        "abuse_score":   data["abuse_score"],
        "total_reports": data["total_reports"],
        "country":       data["country"],
        "isp":           data["isp"],
        "is_tor":        data["is_tor"],
        "last_reported": "2024-01-15T12:00:00",
        "error":         None,
        "mock":          True,
    }


# ── DNS lookup ─────────────────────────────────────────────────────────────

def lookup_dns(target: str) -> dict:
    """
    Perform forward or reverse DNS lookup.
    - Domain → resolves to IPs
    - IP    → reverse PTR lookup
    """
    try:
        import ipaddress
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    try:
        if is_ip:
            hostname = socket.gethostbyaddr(target)[0]
            return {
                "source":     "dns",
                "target":     target,
                "type":       "reverse",
                "hostname":   hostname,
                "error":      None,
            }
        else:
            ips = list(set(
                info[4][0]
                for info in socket.getaddrinfo(target, None)
            ))
            return {
                "source":     "dns",
                "target":     target,
                "type":       "forward",
                "resolved_ips": ips,
                "error":      None,
            }
    except socket.herror as e:
        return {"source": "dns", "target": target, "type": "reverse", "hostname": "no PTR record", "error": str(e)}
    except socket.gaierror as e:
        return {"source": "dns", "target": target, "type": "forward", "resolved_ips": [], "error": str(e)}


# ── Shared helpers ─────────────────────────────────────────────────────────

def _not_found(source: str, target: str) -> dict:
    return {"source": source, "target": target, "error": "not_found",
            "malicious": 0, "suspicious": 0, "clean": 0, "total": 0}

def _api_error(source: str, target: str, message: str) -> dict:
    return {"source": source, "target": target, "error": message}