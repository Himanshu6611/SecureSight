#!/usr/bin/env python3
"""
scripts/train_ensemble.py
--------------------------
Train a weighted soft-voting ensemble (LR + RF + DT) on URL features.
Applies SMOTE for class balancing, GridSearchCV for hyperparameter tuning,
and saves the model + metadata.
"""

import os
import sys
import json
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
import joblib

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

warnings.filterwarnings("ignore")

ROOT          = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FEATURES_PATH = os.path.join(ROOT, "data", "features.parquet")
MODEL_DIR     = os.path.join(ROOT, "models")
MODEL_PATH    = os.path.join(MODEL_DIR, "ensemble.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "metadata.json")

RANDOM_STATE = 42
TEST_SIZE    = 0.20
CV_FOLDS     = 5

def load_features():
    if not os.path.exists(FEATURES_PATH):
        print(f"[ERROR] {FEATURES_PATH} not found. Run feature_engineering.py first.")
        sys.exit(1)
    df = pd.read_parquet(FEATURES_PATH)
    X = df.drop(columns=["label"])
    y = df["label"].astype(int)
    return X, y

def tune(estimator, param_grid, X_train, y_train, cv, name: str):
    """Run GridSearchCV and return the best estimator."""
    gs = GridSearchCV(
        estimator, param_grid,
        cv=cv, scoring="roc_auc",
        n_jobs=-1, verbose=0, refit=True,
    )
    gs.fit(X_train, y_train)
    print(f"  [{name}] best params: {gs.best_params_}  AUC={gs.best_score_:.4f}")
    return gs.best_estimator_

def main() -> None:
    print("=" * 60)
    print("Secure Sight -- URL Ensemble Training")
    print("=" * 60)

    X, y = load_features()
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

    print("\n  Tuning base estimators ...")

    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            solver="lbfgs", max_iter=1000,
            class_weight="balanced", random_state=RANDOM_STATE,
        )),
    ])
    lr_grid = {"lr__C": [0.1, 0.5, 1.0, 5.0, 10.0]}
    lr_best = tune(lr_pipe, lr_grid, X_res, y_res, cv, "LogisticRegression")

    rf = RandomForestClassifier(
        random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
    )
    rf_grid = {
        "n_estimators": [200, 300],
        "max_depth":    [15, 20, None],
        "min_samples_split": [2, 5],
    }
    rf_best = tune(rf, rf_grid, X_res, y_res, cv, "RandomForest")

    dt = DecisionTreeClassifier(
        random_state=RANDOM_STATE, class_weight="balanced"
    )
    dt_grid = {
        "max_depth":       [8, 12, None],
        "min_samples_leaf": [1, 3, 5],
    }
    dt_best = tune(dt, dt_grid, X_res, y_res, cv, "DecisionTree")

    print("\n  Building voting ensemble ...")
    ensemble = VotingClassifier(
        estimators=[
            ("lr", lr_best),
            ("rf", rf_best),
            ("dt", dt_best),
        ],
        voting="soft",
        weights=[0.2, 0.6, 0.2],
    )
    ensemble.fit(X_res, y_res)

    y_pred  = ensemble.predict(X_test)
    y_proba = ensemble.predict_proba(X_test)[:, 1]

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
    joblib.dump(ensemble, MODEL_PATH, compress=3)
    print(f"  [OK] Model saved -> {MODEL_PATH}")

    def _get_params(est):
        if hasattr(est, "named_steps"):
            return {k: v for step in est.named_steps.values()
                    for k, v in step.get_params().items()}
        return est.get_params()

    metadata = {
        "trained_on": {
            "n_samples":  int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "feature_names": list(X.columns),
            "date": pd.Timestamp.now().isoformat(),
        },
        "model_params": {
            "voting_weights": [0.2, 0.6, 0.2],
            "base_estimators": {
                "lr": _get_params(lr_best),
                "rf": _get_params(rf_best),
                "dt": _get_params(dt_best),
            },
        },
        "metrics": metrics,
    }

    with open(METADATA_PATH, "w") as fh:
        json.dump(metadata, fh, indent=2, default=str)
    print(f"  [OK] Metadata saved -> {METADATA_PATH}")
    print("=" * 60)

if __name__ == "__main__":
    main()
