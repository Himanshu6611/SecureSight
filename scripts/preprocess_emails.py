#!/usr/bin/env python3
"""
scripts/preprocess_emails.py
-----------------------------
Load all email datasets, combine subject + body, extract features,
and write data/email_features.parquet.

Dataset column map
------------------
phishing_email.csv  : text_combined, label
CEAS_08.csv         : subject, body, label
Enron.csv           : subject, body, label
Ling.csv            : subject, body, label
Nazario.csv         : subject, body, label
Nigerian_Fraud.csv  : subject, body, label
SpamAssasin.csv     : subject, body, label
"""

import os
import sys
import warnings
import pandas as pd
from concurrent.futures import ProcessPoolExecutor, as_completed

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

warnings.filterwarnings("ignore")

ROOT     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW_DIR  = os.path.join(ROOT, "data", "raw")
OUT_PATH = os.path.join(ROOT, "data", "email_features.parquet")

sys.path.insert(0, ROOT)
from utils.email_extraction import extract_email_features

DATASETS = [
    ("phishing_email.csv",  "text_combined", "label"),
    ("CEAS_08.csv",         None,            "label"),
    ("Enron.csv",           None,            "label"),
    ("Ling.csv",            None,            "label"),
    ("Nazario.csv",         None,            "label"),
    ("Nigerian_Fraud.csv",  None,            "label"),
    ("SpamAssasin.csv",     None,            "label"),
]

def _to_binary_label(val) -> int:
    try:
        v = int(val)
        return 1 if v == 1 else 0
    except (ValueError, TypeError):
        return -1

def _combine_text(row, text_col) -> str:
    if text_col:
        return str(row.get(text_col, "") or "")
    subject = str(row.get("subject", "") or "")
    body    = str(row.get("body",    "") or "")
    return (subject + " " + body).strip()

def _extract_row(args):
    text, label = args
    feats = extract_email_features(text)
    feats["label"] = label
    return feats

def load_dataset(filename: str, text_col, label_col: str) -> pd.DataFrame:
    path = os.path.join(RAW_DIR, filename)
    if not os.path.exists(path):
        print(f"  [!] Missing: {filename}")
        return pd.DataFrame()

    print(f"  Loading {filename} ... ", end="", flush=True)
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as exc:
        print(f"ERROR ({exc})")
        return pd.DataFrame()

    lc = next((c for c in [label_col, "Label", "Class", "Result"] if c in df.columns), None)
    if lc is None:
        print(f"no label column found (cols: {df.columns.tolist()}) - skipped")
        return pd.DataFrame()

    if text_col and text_col not in df.columns:
        text_col = None

    if text_col:
        texts = df[text_col].fillna("").astype(str)
    else:
        sub  = df.get("subject", pd.Series([""] * len(df))).fillna("").astype(str)
        body = df.get("body",    pd.Series([""] * len(df))).fillna("").astype(str)
        texts = sub + " " + body

    labels = df[lc].apply(_to_binary_label)

    mask = (labels >= 0) & (texts.str.strip() != "")
    texts  = texts[mask].reset_index(drop=True)
    labels = labels[mask].reset_index(drop=True)

    print(f"{len(texts):,} rows (phish={int((labels==1).sum()):,}, legit={int((labels==0).sum()):,})")
    return pd.DataFrame({"text": texts, "label": labels})

def main() -> None:
    print("=" * 60)
    print("Secure Sight -- Email Preprocessing")
    print("=" * 60)

    frames: list[pd.DataFrame] = []
    for filename, text_col, label_col in DATASETS:
        df = load_dataset(filename, text_col, label_col)
        if not df.empty:
            frames.append(df)

    if not frames:
        print("[ERROR] No email data loaded - aborting.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Total emails: {len(combined):,}")

    print("  Extracting features ... ", end="", flush=True)
    pairs = list(zip(combined["text"], combined["label"]))

    results = []
    try:
        with ProcessPoolExecutor() as pool:
            futures = {pool.submit(_extract_row, p): i for i, p in enumerate(pairs)}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    pass
    except Exception:
        results = [_extract_row(p) for p in pairs]

    feat_df = pd.DataFrame(results)
    feat_df["label"] = feat_df["label"].astype(int)
    feat_df = feat_df.dropna().reset_index(drop=True)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    feat_df.to_parquet(OUT_PATH, index=False)

    phish = int((feat_df["label"] == 1).sum())
    legit = int((feat_df["label"] == 0).sum())
    print(f"done")
    print(f"\n  [OK] Saved {len(feat_df):,} rows -> {OUT_PATH}")
    print(f"    Phishing : {phish:,}  ({phish/len(feat_df)*100:.1f}%)")
    print(f"    Legit    : {legit:,}  ({legit/len(feat_df)*100:.1f}%)")
    print(f"    Features : {feat_df.shape[1] - 1}")
    print("=" * 60)

if __name__ == "__main__":
    main()
