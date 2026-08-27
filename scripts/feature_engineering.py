#!/usr/bin/env python3
"""
scripts/feature_engineering.py
--------------------------------
Read data/cleaned.csv, extract URL features in parallel, and write
data/features.parquet.
"""

import os
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

warnings.filterwarnings("ignore")

ROOT          = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLEANED_PATH  = os.path.join(ROOT, "data", "cleaned.csv")
FEATURES_PATH = os.path.join(ROOT, "data", "features.parquet")

sys.path.insert(0, ROOT)
from utils.feature_extraction import extract_features  # noqa: E402


def _extract_row(args):
    """Worker: (url, label) -> feature dict with label."""
    url, label = args
    try:
        feats = extract_features(url)
        feats["label"] = label
        return feats
    except Exception:
        return None


def main() -> None:
    print("=" * 60)
    print("Secure Sight -- URL Feature Engineering")
    print("=" * 60)

    if not os.path.exists(CLEANED_PATH):
        print(f"[ERROR] {CLEANED_PATH} not found. Run preprocess.py first.")
        sys.exit(1)

    df = pd.read_csv(CLEANED_PATH)
    print(f"  Loaded {len(df):,} URLs from cleaned.csv")

    pairs = list(zip(df["url"], df["label"]))
    total = len(pairs)
    results = []
    skipped = 0

    print("  Extracting features (parallel) ...")
    try:
        with ProcessPoolExecutor() as pool:
            futures = {pool.submit(_extract_row, p): i for i, p in enumerate(pairs)}
            done = 0
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res is not None:
                    results.append(res)
                else:
                    skipped += 1
                if done % 10_000 == 0 or done == total:
                    pct = done / total * 100
                    print(f"    {done:,}/{total:,}  ({pct:.1f}%)", end="\r", flush=True)
    except Exception:
        print("  (parallel failed - running sequentially)")
        for i, p in enumerate(pairs):
            res = _extract_row(p)
            if res is not None:
                results.append(res)
            else:
                skipped += 1
            if (i + 1) % 10_000 == 0 or (i + 1) == total:
                pct = (i + 1) / total * 100
                print(f"    {i+1:,}/{total:,}  ({pct:.1f}%)", end="\r", flush=True)

    print()

    feat_df = pd.DataFrame(results)
    feat_df["label"] = feat_df["label"].astype(int)
    feat_df = feat_df.dropna().reset_index(drop=True)

    os.makedirs(os.path.dirname(FEATURES_PATH), exist_ok=True)
    feat_df.to_parquet(FEATURES_PATH, index=False)

    phish = int((feat_df["label"] == 1).sum())
    legit = int((feat_df["label"] == 0).sum())
    print(f"\n  [OK] Saved {len(feat_df):,} rows -> {FEATURES_PATH}")
    print(f"    Phishing : {phish:,}  ({phish/len(feat_df)*100:.1f}%)")
    print(f"    Legit    : {legit:,}  ({legit/len(feat_df)*100:.1f}%)")
    print(f"    Features : {feat_df.shape[1] - 1}")
    if skipped:
        print(f"    Skipped  : {skipped:,} rows (extraction errors)")
    print("=" * 60)


if __name__ == "__main__":
    main()
