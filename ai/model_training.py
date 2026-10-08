"""
Behaviour model — aggregates raw activity logs into per-user feature rows
and trains an unsupervised anomaly detector (Isolation Forest).

All work is done locally; no external AI services are used.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

# scikit-learn is heavy and can fail to import in locked-down Windows
# environments (Application Control policies block specific native DLLs).
# Import it lazily and fail soft — the rest of the application still works.
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE: bool = True
    SKLEARN_IMPORT_ERROR: str | None = None
except Exception as _exc:  # pragma: no cover - environment dependent
    IsolationForest = None  # type: ignore[assignment]
    StandardScaler = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False
    SKLEARN_IMPORT_ERROR = str(_exc)

from config.settings import FEATURE_COLUMNS, MODEL_FILE
from database import db_manager as db
from utils.helpers import iso_now, log

if not SKLEARN_AVAILABLE:
    log.warning("scikit-learn unavailable: %s", SKLEARN_IMPORT_ERROR)


SYNTHETIC_SAMPLE_SIZE: int = 800  # how many synthetic "normal" rows to generate


# -----------------------------------------------------------
# Feature engineering
# -----------------------------------------------------------
def build_user_features(user_id: int, window_minutes: int = 60) -> Dict[str, float]:
    """Aggregate the activity logs for a user into a single feature vector."""
    cutoff = (datetime.now() - timedelta(minutes=window_minutes)).isoformat()
    events = db.activity_for_user(user_id, since_iso=cutoff)
    feature = {col: 0.0 for col in FEATURE_COLUMNS}

    # login_hour is the latest login time within the window
    login_hours: List[int] = []
    for ev in events:
        ev_type = ev.get("event_type", "")
        feature["failed_login_count"] += 1 if ev_type == "failed_login" else 0
        feature["files_accessed"] += float(ev.get("files_accessed", 0) or 0)
        feature["download_volume_mb"] += float(ev.get("download_mb", 0) or 0)
        feature["usb_activity"] += 1 if (ev.get("usb_activity") or 0) > 0 else 0
        feature["privileged_access_count"] += 1 if (ev.get("privileged") or 0) > 0 else 0
        feature["data_transfer_mb"] += float(ev.get("data_transfer_mb", 0) or 0)
        if ev.get("login_hour") is not None:
            login_hours.append(int(ev["login_hour"]))
    if login_hours:
        feature["login_hour"] = float(login_hours[-1])
    return feature


def features_dataframe(user_ids: Optional[List[int]] = None) -> pd.DataFrame:
    """Return a DataFrame with one row per user and FEATURE_COLUMNS columns."""
    if user_ids is None:
        user_ids = [u["user_id"] for u in db.list_users()]
    rows = [build_user_features(uid) for uid in user_ids]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS).fillna(0.0)
    return df


def load_model() -> Optional[IsolationForest]:
    """Load the persisted model if it exists."""
    if not MODEL_FILE.exists():
        return None
    try:
        bundle = joblib.load(MODEL_FILE)
        if isinstance(bundle, dict) and "model" in bundle:
            bundle["model"].scaler = bundle.get("scaler")
            return bundle["model"]
        return bundle
    except Exception as exc:
        log.warning("Could not load model: %s", exc)
        return None


def save_model(model: IsolationForest, scaler: StandardScaler, metadata: Dict) -> None:
    """Persist the trained model alongside its scaler and metadata."""
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "metadata": metadata,
            "feature_columns": FEATURE_COLUMNS,
        },
        MODEL_FILE,
    )
    log.info("Saved trained model to %s", MODEL_FILE)


def model_status() -> Dict:
    """Return a small dict describing the model file (used by the AI page)."""
    if not MODEL_FILE.exists():
        return {
            "trained": False,
            "path": str(MODEL_FILE),
            "metadata": {},
        }
    try:
        bundle = joblib.load(MODEL_FILE)
        meta = bundle.get("metadata", {}) if isinstance(bundle, dict) else {}
        return {
            "trained": True,
            "path": str(MODEL_FILE),
            "metadata": meta,
            "feature_columns": bundle.get("feature_columns", FEATURE_COLUMNS)
                if isinstance(bundle, dict) else FEATURE_COLUMNS,
        }
    except Exception as exc:  # pragma: no cover
        log.warning("Could not read model status: %s", exc)
        return {"trained": False, "path": str(MODEL_FILE), "metadata": {}, "error": str(exc)}


# -----------------------------------------------------------
# Synthetic data + training
# -----------------------------------------------------------
def _generate_synthetic_dataframe() -> pd.DataFrame:
    """Create a DataFrame that mimics *normal* employee behaviour."""
    rng = np.random.default_rng(seed=42)
    n = SYNTHETIC_SAMPLE_SIZE
    df = pd.DataFrame({
        "login_hour":             rng.normal(loc=9.0, scale=1.2, size=n).clip(6, 18),
        "failed_login_count":     rng.poisson(lam=0.2, size=n),
        "files_accessed":         rng.normal(loc=40.0, scale=12.0, size=n).clip(0, 200),
        "download_volume_mb":     rng.normal(loc=30.0, scale=15.0, size=n).clip(0, 200),
        "usb_activity":           rng.binomial(1, 0.02, size=n),
        "privileged_access_count":rng.binomial(1, 0.05, size=n),
        "data_transfer_mb":       rng.normal(loc=20.0, scale=10.0, size=n).clip(0, 200),
    })
    return df


def train_isolation_forest(force: bool = False) -> Dict:
    """Train (or retrain) the Isolation Forest on synthetic + real activity."""
    if not SKLEARN_AVAILABLE:
        raise RuntimeError(
            f"scikit-learn is not importable in this environment: {SKLEARN_IMPORT_ERROR}"
        )
    real_df = features_dataframe()
    synthetic_df = _generate_synthetic_dataframe()
    training_df = pd.concat([synthetic_df, real_df], ignore_index=True).fillna(0.0)

    scaler = StandardScaler()
    X = scaler.fit_transform(training_df[FEATURE_COLUMNS].values)

    model = IsolationForest(
        n_estimators=120,
        contamination=0.08,
        random_state=42,
        n_jobs=1,
    )
    model.fit(X)

    metadata = {
        "trained_at": iso_now(),
        "rows_used": int(len(training_df)),
        "feature_columns": FEATURE_COLUMNS,
        "contamination": 0.08,
        "synthetic_samples": SYNTHETIC_SAMPLE_SIZE,
        "real_samples": int(len(real_df)),
    }
    save_model(model, scaler, metadata)
    return metadata


# -----------------------------------------------------------
# Inference
# -----------------------------------------------------------
def predict_anomalies(user_ids: Optional[List[int]] = None) -> List[Dict]:
    """Run inference for one or more users and return human-readable results."""
    bundle = _load_bundle()
    if bundle is None:
        log.warning("Model is not trained; cannot predict.")
        return []

    model, scaler, meta = bundle
    if user_ids is None:
        user_ids = [u["user_id"] for u in db.list_users()]

    df = features_dataframe(user_ids)
    if df.empty:
        return []

    X = scaler.transform(df[FEATURE_COLUMNS].values)
    raw_scores = model.decision_function(X)
    predictions = model.predict(X)  # -1 anomaly, 1 normal

    explanations = _top_contributors(df, model, scaler)

    results: List[Dict] = []
    for idx, uid in enumerate(user_ids):
        user = db.get_user(uid)
        results.append({
            "user_id": uid,
            "user_name": user["name"] if user else f"User {uid}",
            "anomaly_score": float(raw_scores[idx]),
            "is_anomaly": bool(predictions[idx] == -1),
            "label": "ANOMALY" if predictions[idx] == -1 else "NORMAL",
            "top_factors": explanations[idx],
            "features": {col: float(df.iloc[idx][col]) for col in FEATURE_COLUMNS},
        })
    return results


def _load_bundle():
    if not MODEL_FILE.exists():
        return None
    try:
        bundle = joblib.load(MODEL_FILE)
        if isinstance(bundle, dict):
            return bundle["model"], bundle["scaler"], bundle.get("metadata", {})
        return bundle, None, {}
    except Exception as exc:
        log.warning("Could not load model bundle: %s", exc)
        return None


def _top_contributors(df: pd.DataFrame, model: IsolationForest, scaler: StandardScaler) -> List[Dict]:
    """Return the top-2 features that drove each anomaly score."""
    X = scaler.transform(df[FEATURE_COLUMNS].values)
    contributions: List[Dict] = []
    if hasattr(model, "estimators_"):
        # Compute the average depth-difference contribution per feature.
        importances = np.zeros(len(FEATURE_COLUMNS))
        for tree in model.estimators_:
            try:
                # Feature importances are not directly available for IsolationForest;
                # approximate using feature stddev on splits.
                importances += tree.feature_importances_
            except Exception:
                continue
        if importances.sum() > 0:
            importances = importances / importances.sum()
        else:
            importances = np.ones(len(FEATURE_COLUMNS)) / len(FEATURE_COLUMNS)
    else:  # pragma: no cover
        importances = np.ones(len(FEATURE_COLUMNS)) / len(FEATURE_COLUMNS)

    for row in X:
        # Score is the weighted absolute scaled value.
        abs_row = np.abs(row)
        weighted = abs_row * importances
        top_idx = np.argsort(weighted)[::-1][:3]
        contributors = [
            {
                "feature": FEATURE_COLUMNS[i],
                "value": float(abs_row[i]),
                "weight": float(importances[i]),
                "label": FEATURE_COLUMNS[i].replace("_", " "),
            }
            for i in top_idx
        ]
        contributions.append(contributors)
    return contributions