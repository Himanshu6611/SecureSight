# reputation.py
#!/usr/bin/env python3
"""
utils/reputation.py
-------------------
Risk scoring helpers that complement the ML prediction.
"""

import os
import datetime
import socket
import ssl
import json
import hashlib
import requests
import pandas as pd
try:
    import whois
except ImportError:
    whois = None
from urllib.parse import urlparse

# ----------------------------------------------------------------------
# Load local blacklist (CSV with a single column “domain”).  You can
# update it periodically (e.g., from PhishTank, Spamhaus, etc.).
BLACKLIST_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "blacklist.csv")
)

def _load_blacklist() -> set:
    if not os.path.exists(BLACKLIST_PATH):
        return set()
    df = pd.read_csv(BLACKLIST_PATH, header=None, names=["domain"])
    return set(df["domain"].str.lower().unique())

BLACKLIST = _load_blacklist()

# ----------------------------------------------------------------------
def _domain_age_in_days(domain: str) -> int:
    """Return domain age in days (WHOIS).  If unavailable, return a large default."""
    if whois is None or not domain:
        return 0
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list) and len(creation) > 0:
            creation = creation[0]
        if isinstance(creation, str):
            try:
                creation = pd.to_datetime(creation).to_pydatetime()
            except Exception:
                creation = None
        if isinstance(creation, datetime.datetime):
            # Ensure creation is naive for comparison if it is, or make both aware
            if creation.tzinfo is not None:
                age = (datetime.datetime.now(datetime.timezone.utc) - creation).days
            else:
                age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - creation).days
            return max(age, 0)
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(orig_timeout)
    # If WHOIS fails, treat as “new” domain (high risk)
    return 0

# ----------------------------------------------------------------------
def _has_valid_ssl(url: str) -> bool:
    """Perform a simple HEAD request with SSL verification."""
    try:
        resp = requests.head(url, timeout=2, verify=True, allow_redirects=True)
        return resp.ok
    except Exception:
        return False

# ----------------------------------------------------------------------
def _blacklist_hit(domain: str) -> int:
    """1 if domain (or its top‑level domain) appears in local blacklist."""
    return int(domain.lower() in BLACKLIST)

# ----------------------------------------------------------------------
def compute_risk_score(url: str, feature_dict: dict) -> float:
    """
    Weighted risk score (0‑100).  Feature dict is the output of
    utils.feature_extraction.extract_features for the same URL.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    # ---------- Reputation signals ----------
    age_days = _domain_age_in_days(hostname)
    ssl_ok = _has_valid_ssl(url)
    blacklist = _blacklist_hit(hostname)

    # ---------- Normalised numeric values ----------
    # Age: newer --> higher risk, so invert.
    age_score = 1 - min(age_days / 3650, 1)           # 0‑1 (10 years → 0 risk)
    ssl_score = 0 if ssl_ok else 1                  # 0 (good) or 1 (bad)
    blacklist_score = blacklist                    # 0 or 1

    # ---------- Feature‑based scores ----------
    # token_hits and suspicious chars have a direct linear mapping.
    token_score = min(feature_dict["token_hits"] / 10, 1)
    ip_score = feature_dict["has_ip"]
    https_score = 0 if feature_dict["https"] else 1
    entropy_score = min(feature_dict["entropy"] / 5, 1)   # empirical cap

    # ---------- Weighted sum (tweakable) ----------
    weights = {
        "age": 0.25,
        "ssl": 0.20,
        "blacklist": 0.30,
        "token": 0.10,
        "ip": 0.05,
        "https": 0.05,
        "entropy": 0.05,
    }

    raw_score = (
        weights["age"] * age_score +
        weights["ssl"] * ssl_score +
        weights["blacklist"] * blacklist_score +
        weights["token"] * token_score +
        weights["ip"] * ip_score +
        weights["https"] * https_score +
        weights["entropy"] * entropy_score
    )
    # Scale to 0‑100
    return round(raw_score * 100, 2)

# ----------------------------------------------------------------------
def explain_risk(url: str, feature_dict: dict) -> dict:
    """
    Return a dictionary that breaks down each component of the risk score.
    Helpful for UI “Why?” view.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    age_days = _domain_age_in_days(hostname)
    ssl_ok = _has_valid_ssl(url)
    blacklist = _blacklist_hit(hostname)

    # Normalise components exactly as used in compute_risk_score
    age_score = 1 - min(age_days / 3650, 1)
    ssl_score = 0 if ssl_ok else 1
    blacklist_score = blacklist
    token_score = min(feature_dict["token_hits"] / 10, 1)
    ip_score = feature_dict["has_ip"]
    https_score = 0 if feature_dict["https"] else 1
    entropy_score = min(feature_dict["entropy"] / 5, 1)

    # Assemble breakdown
    breakdown = {
        "Domain age (days)": age_days,
        "Age risk (0‑1)": round(age_score, 3),
        "SSL valid?": ssl_ok,
        "SSL risk (0‑1)": ssl_score,
        "Blacklisted?": bool(blacklist),
        "Blacklist risk (0‑1)": blacklist_score,
        "Suspicious token count": feature_dict["token_hits"],
        "Token risk (0‑1)": round(token_score, 3),
        "IP address in host": bool(feature_dict["has_ip"]),
        "IP risk (0‑1)": ip_score,
        "HTTPS usage": bool(feature_dict["https"]),
        "HTTPS risk (0‑1)": https_score,
        "URL entropy": round(feature_dict["entropy"], 3),
        "Entropy risk (0‑1)": round(entropy_score, 3),
    }
    return breakdown
