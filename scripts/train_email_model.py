#!/usr/bin/env python3
"""
scripts/train_email_model.py
-----------------------------
Train a tuned Random Forest on email features with SMOTE balancing.
Saves models/email_model.pkl and prints a full evaluation report.
"""

import os
import sys
import json
import warnings

import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
)
from imblearn.over_sampling import SMOTE
import joblib

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

warnings.filterwarnings("ignore")

ROOT          = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FEATURES_PATH = os.path.join(ROOT, "data", "email_features.parquet")
MODEL_DIR     = os.path.join(ROOT, "models")
MODEL_PATH    = os.path.join(MODEL_DIR, "email_model.pkl")
META_PATH     = os.path.join(MODEL_DIR, "email_metadata.json")

RANDOM_STATE = 42
TEST_SIZE    = 0.20
CV_FOLDS     = 5

def main() -> None:
    print("=" * 60)
    print("Secure Sight -- Email Model Training")
    print("=" * 60)

    if not os.path.exists(FEATURES_PATH):
        print(f"[ERROR] {FEATURES_PATH} not found. Run preprocess_emails.py first.")
        sys.exit(1)

    df = pd.read_parquet(FEATURES_PATH)
    X  = df.drop(columns=["label"])
    y  = df["label"].astype(int)

    print(f"  Dataset : {len(X):,} samples, {X.shape[1]} features")
    print(f"  Classes : phish={int(y.sum()):,}  legit={int((y==0).sum()):,}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"  Train   : {len(X_train):,}   Test: {len(X_test):,}")

    print("\n  Applying SMOTE ...")
    sm = SMOTE(random_state=RANDOM_STATE)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    print(f"  After SMOTE: {len(X_res):,} samples (balanced)")

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    print("\n  Tuning Random Forest ...")
    rf = RandomForestClassifier(
        random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
    )
    rf_grid = {
        "n_estimators": [200, 300],
        "max_depth":    [10, 20, None],
        "min_samples_split": [2, 5],
        "max_features": ["sqrt", "log2"],
    }
    gs_rf = GridSearchCV(rf, rf_grid, cv=cv, scoring="roc_auc", n_jobs=-1, verbose=0)
    gs_rf.fit(X_res, y_res)
    rf_best = gs_rf.best_estimator_
    print(f"  RF best params: {gs_rf.best_params_}  AUC={gs_rf.best_score_:.4f}")

    print("\n  Tuning Gradient Boosting ...")
    gb = GradientBoostingClassifier(random_state=RANDOM_STATE)
    gb_grid = {
        "n_estimators":   [100, 200],
        "max_depth":      [3, 5],
        "learning_rate":  [0.05, 0.1],
        "subsample":      [0.8, 1.0],
    }
    gs_gb = GridSearchCV(gb, gb_grid, cv=cv, scoring="roc_auc", n_jobs=-1, verbose=0)
    gs_gb.fit(X_res, y_res)
    gb_best = gs_gb.best_estimator_
    print(f"  GB best params: {gs_gb.best_params_}  AUC={gs_gb.best_score_:.4f}")

    print("\n  Building email voting ensemble (RF + GB) ...")
    model = VotingClassifier(
        estimators=[("rf", rf_best), ("gb", gb_best)],
        voting="soft",
        weights=[0.5, 0.5],
    )
    model.fit(X_res, y_res)

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy":  float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_test, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc":   float(roc_auc_score(y_test, y_proba)),
    }

    print("\n  === Test-set Performance ===")
    for k, v in metrics.items():
        print(f"    {k.title():<12}: {v:.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH, compress=3)
    print(f"  [OK] Email model saved -> {MODEL_PATH}")

    metadata = {
        "trained_on": {
            "n_samples":  int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "feature_names": list(X.columns),
            "date": pd.Timestamp.now().isoformat(),
        },
        "model_params": {
            "type": "VotingClassifier(RF + GradientBoosting)",
            "weights": [0.5, 0.5],
            "rf_params": rf_best.get_params(),
            "gb_params": gb_best.get_params(),
        },
        "metrics": metrics,
    }
    with open(META_PATH, "w") as fh:
        json.dump(metadata, fh, indent=2, default=str)
    print(f"  [OK] Metadata saved -> {META_PATH}")
    print("=" * 60)

if __name__ == "__main__":
    main()
