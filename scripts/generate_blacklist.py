#!/usr/bin/env python3
"""
scripts/generate_blacklist.py
------------------------------
Build data/blacklist.csv from the phishing URLs in cleaned.csv.
Extracts the registered domain (eTLD+1) from every phishing URL,
deduplicates, and writes the top domains sorted by frequency.

This gives the reputation scorer a real, data-driven blacklist.
"""

import os
import sys
import pandas as pd
import tldextract

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ROOT         = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLEANED_PATH = os.path.join(ROOT, "data", "cleaned.csv")
OUT_PATH     = os.path.join(ROOT, "data", "blacklist.csv")

SEED_DOMAINS = [
    "phishing-site.net",
    "malicious-link.org",
    "suspicious-login.com",
    "bank-verify-secure.tk",
    "paypal-secure-login.com",
    "account-verify-update.com",
    "secure-banking-login.net",
    "login-verify-account.com",
    "update-your-account.net",
    "webscr-paypal.com",
    "signin-amazon-secure.com",
    "apple-id-verify.com",
    "microsoft-account-alert.com",
    "netflix-billing-update.com",
    "irs-tax-refund.com",
    "fedex-delivery-tracking.com",
    "dhl-parcel-tracking.net",
    "covid-relief-fund.com",
    "crypto-wallet-verify.com",
    "binance-secure-login.com",
]

def extract_domain(url: str) -> str:
    """Return eTLD+1 (e.g. 'example.com') or empty string."""
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ""

def main() -> None:
    print("=" * 60)
    print("Secure Sight -- Blacklist Generation")
    print("=" * 60)

    if not os.path.exists(CLEANED_PATH):
        print(f"[ERROR] {CLEANED_PATH} not found. Run preprocess.py first.")
        sys.exit(1)

    df = pd.read_csv(CLEANED_PATH)
    phish_urls = df[df["label"] == 1]["url"]
    print(f"  Phishing URLs in cleaned.csv: {len(phish_urls):,}")

    print("  Extracting domains ...")
    domains = phish_urls.apply(extract_domain)
    domains = domains[domains != ""]

    freq = domains.value_counts()
    unique_domains = freq.index.tolist()
    print(f"  Unique phishing domains found: {len(unique_domains):,}")

    all_domains = list(dict.fromkeys(SEED_DOMAINS + unique_domains))

    out_df = pd.DataFrame({"domain": all_domains})
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    out_df.to_csv(OUT_PATH, index=False)

    print(f"\n  [OK] Blacklist saved -> {OUT_PATH}")
    print(f"    Total entries : {len(out_df):,}")
    print(f"    Seed entries  : {len(SEED_DOMAINS)}")
    print(f"    Data-driven   : {len(unique_domains):,}")
    print("=" * 60)

if __name__ == "__main__":
    main()
