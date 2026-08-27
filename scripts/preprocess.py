#!/usr/bin/env python3
"""
scripts/preprocess.py
---------------------
Combine all URL datasets, deduplicate, normalise and write data/cleaned.csv.

Sources used:
  - PhiUSIIL_Phishing_URL_Dataset.csv  (235 795 rows, label col = 'label')
  - Training Dataset.arff              (UCI, feature-only - no raw URL, skipped)
"""

import os
import re
import sys
import pandas as pd
from urllib.parse import urlparse

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# -- Paths --------------------------------------------------------------
ROOT     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW_DIR  = os.path.join(ROOT, "data", "raw")
OUT_FILE = os.path.join(ROOT, "data", "cleaned.csv")

# -- Helpers ------------------------------------------------------------
def normalise_url(url: str) -> str:
    """Force scheme, lowercase netloc, strip trailing slash & whitespace."""
    url = str(url).strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    try:
        p = urlparse(url)
        netloc = p.netloc.lower()
        if netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif netloc.endswith(":443"):
            netloc = netloc[:-4]
        path = p.path.rstrip("/") or "/"
        return f"{p.scheme}://{netloc}{path}"
    except Exception:
        return ""


def _to_binary_label(val) -> int:
    """Map any label encoding to 0 (legit) / 1 (phishing)."""
    try:
        v = int(val)
    except (ValueError, TypeError):
        return -1
    if v == 1:
        return 1
    if v in (0, -1):
        return 0
    return -1


# -- Loaders ------------------------------------------------------------
def load_phiusiil(path: str) -> pd.DataFrame:
    """PhiUSIIL dataset: columns URL + label (0/1)."""
    print("  Loading PhiUSIIL ... ", end="", flush=True)
    df = pd.read_csv(path, usecols=["URL", "label"], low_memory=False)
    df = df.rename(columns={"URL": "url"})
    df["label"] = df["label"].apply(_to_binary_label)
    df = df[df["label"] >= 0]
    print(f"{len(df):,} rows")
    return df[["url", "label"]]


def load_arff_urls(path: str) -> pd.DataFrame:
    """UCI ARFF - only useful if it contains a URL column."""
    print("  Loading UCI ARFF ... ", end="", flush=True)
    try:
        from scipy.io import arff
        data, meta = arff.loadarff(path)
        df = pd.DataFrame(data)
        for col in df.select_dtypes([object]).columns:
            df[col] = df[col].str.decode("utf-8", errors="ignore")
        url_col = next((c for c in df.columns if c.upper() == "URL"), None)
        if url_col is None:
            print("no URL column - skipped")
            return pd.DataFrame(columns=["url", "label"])
        label_col = "Result" if "Result" in df.columns else df.columns[-1]
        df = df.rename(columns={url_col: "url", label_col: "label"})
        df["label"] = df["label"].apply(_to_binary_label)
        df = df[df["label"] >= 0]
        print(f"{len(df):,} rows")
        return df[["url", "label"]]
    except Exception as exc:
        print(f"failed ({exc})")
        return pd.DataFrame(columns=["url", "label"])


# -- Main ---------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("Secure Sight -- URL Preprocessing")
    print("=" * 60)

    all_dfs: list[pd.DataFrame] = []

    phi_path = os.path.join(RAW_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")
    if os.path.exists(phi_path):
        all_dfs.append(load_phiusiil(phi_path))
    else:
        print(f"  [!] PhiUSIIL not found at {phi_path}")

    arff_path = os.path.join(RAW_DIR, "Training Dataset.arff")
    if os.path.exists(arff_path):
        df_arff = load_arff_urls(arff_path)
        if not df_arff.empty:
            all_dfs.append(df_arff)

    if not all_dfs:
        print("[ERROR] No URL datasets found - aborting.")
        sys.exit(1)

    print(f"\n  Merging {len(all_dfs)} source(s) ...")
    df = pd.concat(all_dfs, ignore_index=True)

    print("  Normalising URLs ...")
    df["url"] = df["url"].apply(normalise_url)
    before = len(df)
    df = df[df["url"] != ""].reset_index(drop=True)
    print(f"  Dropped {before - len(df):,} empty/invalid URLs")

    print("  Deduplicating ...")
    before = len(df)
    df = df.drop_duplicates(subset="url", keep="first").reset_index(drop=True)
    print(f"  Removed {before - len(df):,} duplicates")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    df.to_csv(OUT_FILE, index=False)

    phish = int(df["label"].sum())
    legit = len(df) - phish
    print(f"\n  [OK] Saved {len(df):,} rows -> {OUT_FILE}")
    print(f"    Phishing : {phish:,}  ({phish/len(df)*100:.1f}%)")
    print(f"    Legit    : {legit:,}  ({legit/len(df)*100:.1f}%)")
    print("=" * 60)


if __name__ == "__main__":
    main()
