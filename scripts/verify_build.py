"""Verify that this checkout is correctly built and can run Kev end to end.

Runs twelve checks against a throwaway database. Nothing here needs real CERT
data, a network connection, or the user's live insider_threat.db.

    <kev-env>\\Scripts\\python.exe scripts\\verify_build.py
    <kev-env>\\Scripts\\python.exe scripts\\verify_build.py --skip-model

Exit code is 0 when every required check passes. Checks that depend on a GPU
are reported as SKIP (not failure) when CUDA is unavailable, so the script is
useful on a CPU-only machine too.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from datetime import datetime, timedelta

import _bootstrap

_bootstrap.configure_console()
_bootstrap.use_temp_database()

import pandas as pd  # noqa: E402

RESULTS: list = []


def check(label: str, required: bool = True):
    """Decorator: run the function as a named check."""

    def wrap(func):
        RESULTS.append((label, func, required))
        return func

    return wrap


# --------------------------------------------------------------------------- #
# 1. Python version
# --------------------------------------------------------------------------- #
@check("Python version supports the Kev environment (>=3.12,<3.14)")
def check_python_version() -> str:
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 12):
        raise AssertionError(
            f"Python {major}.{minor} is too old. Kev requires >=3.12,<3.14. "
            f"The GUI's f-strings also need 3.12+."
        )
    if (major, minor) >= (3, 14):
        raise AssertionError(f"Python {major}.{minor} is not supported by Kev (<3.14).")
    return f"Python {sys.version.split()[0]}"


# --------------------------------------------------------------------------- #
# 2. Imports
# --------------------------------------------------------------------------- #
@check("Application modules import")
def check_imports() -> str:
    import importlib

    modules = [
        "config.settings",
        "database.db_manager",
        "utils.helpers",
        "engine.risk_engine",
        "engine.event_simulator",
        "monitor.monitor_manager",
        "ai.anomaly_detector",
        "ai.kev_anomaly_detector",
        "ai.kev_feature_adapter",
    ]
    for name in modules:
        importlib.import_module(name)
    return f"{len(modules)} modules"


# --------------------------------------------------------------------------- #
# 3. Database initialisation
# --------------------------------------------------------------------------- #
@check("Database initialises with the source column")
def check_db_init() -> str:
    from database import db_manager as db

    db.init_db(seed=True)
    users = db.list_users()
    assert users, "no users were seeded"
    columns = {r[1] for r in db.fetch_all("PRAGMA table_info(activity_logs)")}
    assert "source" in columns, "activity_logs.source is missing"
    assert db.get_setting("risk_threshold"), "settings table not populated"
    return f"{len(users)} users, activity_logs.source present"


# --------------------------------------------------------------------------- #
# 4. Kev module imports
# --------------------------------------------------------------------------- #
@check("Kev module imports (torch, kev package, feature_builder)")
def check_kev_imports() -> str:
    import torch  # noqa: F401
    from kev.checkpoint import Checkpoint  # noqa: F401

    from ai import kev_feature_adapter as adapter

    bad = not adapter.available()
    if bad:
        raise AssertionError(adapter.unavailable_reason())
    return "torch, kev.checkpoint, feature_builder"


# --------------------------------------------------------------------------- #
# 5. Kev model configuration
# --------------------------------------------------------------------------- #
@check("Kev model configuration matches the published contract")
def check_kev_config() -> str:
    from config.settings import KEV_MODEL_ID, KEV_THRESHOLD
    from ai import kev_anomaly_detector as kev

    assert KEV_MODEL_ID == "joshnavardhan/kev-cert-r42-v3", KEV_MODEL_ID
    assert abs(KEV_THRESHOLD - 0.8279442191123962) < 1e-12, KEV_THRESHOLD
    assert kev.QUESTION["options"] == ["false", "true"], kev.QUESTION
    assert "insider threat" in kev.QUESTION["instr"].lower()
    return f"{KEV_MODEL_ID} @ {KEV_THRESHOLD}"


# --------------------------------------------------------------------------- #
# 6. Feature builder (from the Kev checkout)
# --------------------------------------------------------------------------- #
@check("feature_builder produces the v3 baseline features")
def check_feature_builder() -> str:
    from ai import kev_feature_adapter as adapter

    builder = adapter.load_feature_builder()
    frame = _synthetic_user_days("fb_user", days=12, spike_last=True)
    prepared = builder.prepare_daily_features(frame)

    for column in ("baseline_history", "baseline_anomaly_score", "day_of_week", "is_weekend"):
        assert column in prepared.columns, f"missing {column}"
    for name in adapter.BASE_FEATURE_NAMES:
        assert f"{name}_rel_dev" in prepared.columns, f"missing {name}_rel_dev"

    last = prepared.iloc[-1]
    assert last["baseline_anomaly_score"] > 0, "spiked day should deviate from baseline"
    early = prepared.iloc[0]
    assert early["baseline_anomaly_score"] == 0.0, "first day has no history to deviate from"

    text = builder.row_to_state(last)
    assert text.startswith("Employee activity summary:"), text[:40]
    assert "User baseline anomaly score:" in text
    return f"{len(prepared.columns)} columns, state text {len(text)} chars"


# --------------------------------------------------------------------------- #
# 7. Daily feature adapter (Windows telemetry -> CERT user-days)
# --------------------------------------------------------------------------- #
@check("Windows telemetry adapter aggregates into user-day rows")
def check_adapter() -> str:
    from database import db_manager as db
    from ai import kev_feature_adapter as adapter

    users = db.list_users()
    user_id = int(users[0]["user_id"])

    _insert_activity_days(user_id, days=12)
    daily = adapter.build_daily_table([user_id])
    assert not daily.empty, "adapter produced no rows"
    for name in adapter.BASE_FEATURE_NAMES:
        assert name in daily.columns, f"missing {name}"

    prepared = adapter.build_scoring_rows([user_id])
    assert "baseline_anomaly_score" in prepared.columns
    assert len(adapter.coverage_summary()) == 10, "coverage should describe all ten features"
    return f"{len(daily)} user-days, {len(daily.columns)} columns"


# --------------------------------------------------------------------------- #
# 8. Model loading
# --------------------------------------------------------------------------- #
@check("Kev checkpoint loads", required=False)
def check_model_load() -> str:
    from ai import kev_anomaly_detector as kev

    d = kev.detector()
    if not d.torch_available():
        raise AssertionError("torch unavailable")
    if not d.cuda_available():
        raise AssertionError("CUDA unavailable on this machine (CPU run is much slower)")
    if not d.load():
        raise AssertionError(d.error() or "load() returned False")
    return f"{d.model_reference()} on {d.device()} ({d.gpu_name()})"


# --------------------------------------------------------------------------- #
# 9. Inference on a synthetic user-day
# --------------------------------------------------------------------------- #
@check("Kev inference runs on a synthetic user-day", required=False)
def check_inference() -> str:
    from database import db_manager as db
    from ai import kev_anomaly_detector as kev

    d = kev.detector()
    if not d.is_loaded() and not d.load():
        raise AssertionError(d.error() or "model not loaded")

    user_id = int(db.list_users()[0]["user_id"])
    result = d.score_user(user_id)
    assert result is not None, "score_user returned None"
    assert 0.0 <= result.probability <= 1.0, result.probability
    return f"p={result.probability:.6f} -> {result.label}"


# --------------------------------------------------------------------------- #
# 10. Result object shape
# --------------------------------------------------------------------------- #
@check("Kev result object exposes the documented fields")
def check_result_shape() -> str:
    from ai import kev_anomaly_detector as kev

    expected = {
        "user_id", "user_name", "date", "probability", "threshold", "is_threat",
        "label", "baseline_anomaly_score", "baseline_history", "features",
        "deviations", "feature_coverage", "model",
    }
    payload = kev.KevResult(
        user_id=1, user_name="Test", date="2026-01-01", probability=0.5,
        threshold=0.8279442191123962, is_threat=False, label="NORMAL",
        baseline_anomaly_score=0.0, baseline_history=0,
    ).as_dict()
    missing = expected - set(payload)
    assert not missing, f"missing fields: {sorted(missing)}"
    return f"{len(expected)} fields"


# --------------------------------------------------------------------------- #
# 11. Threshold decision
# --------------------------------------------------------------------------- #
@check("Threshold decision follows the published rule")
def check_threshold() -> str:
    from ai.anomaly_detector import predict_for_all  # noqa: F401
    from config.settings import KEV_THRESHOLD

    def decide(p: float) -> str:
        return "POTENTIAL_INSIDER_THREAT" if p >= KEV_THRESHOLD else "NORMAL"

    assert decide(KEV_THRESHOLD) == "POTENTIAL_INSIDER_THREAT", "boundary is inclusive"
    assert decide(KEV_THRESHOLD - 1e-9) == "NORMAL"
    assert decide(0.99) == "POTENTIAL_INSIDER_THREAT"
    assert decide(0.01) == "NORMAL"
    return f"boundary inclusive at {KEV_THRESHOLD}"


# --------------------------------------------------------------------------- #
# 12. Alert creation path
# --------------------------------------------------------------------------- #
@check("A threat result creates an alert, incident and audit entry")
def check_alert_path() -> str:
    from database import db_manager as db
    from engine.risk_engine import RiskEngine

    user_id = int(db.list_users()[0]["user_id"])
    engine = RiskEngine()
    alerts_before = db.count_alerts()
    incidents_before = len(db.list_incidents())
    audit_before = len(db.list_audit())

    result = {
        "user_id": user_id,
        "user_name": "Test User",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "probability": 0.95,
        "threshold": 0.8279442191123962,
        "is_threat": True,
        "label": "POTENTIAL_INSIDER_THREAT",
        "baseline_anomaly_score": 1.23,
        "baseline_history": 14,
        "features": {"logon_count": 9.0, "file_events": 40.0},
        "feature_coverage": {"logon_count": "proxy", "unique_logon_pcs": "degenerate"},
        "model": "joshnavardhan/kev-cert-r42-v3",
    }

    alert_id = engine.raise_kev_alert(result)
    assert alert_id is not None, "no alert was created"
    assert db.count_alerts() == alerts_before + 1, "alert row missing"
    assert len(db.list_incidents()) == incidents_before + 1, "incident row missing"
    assert len(db.list_audit()) > audit_before, "audit entry missing"

    alert = db.fetch_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    assert alert["event_type"] == "kev_insider_threat"
    assert "0.95" in alert["description"] or "0.9500" in alert["description"]
    assert alert["incident_id"], "alert not linked to an incident"

    # Re-raising for the same user must reuse the open incident and not
    # create a second alert.
    assert engine.raise_kev_alert(result) is None, "duplicate alert created"
    assert len(db.list_incidents()) == incidents_before + 1, "duplicate incident created"

    # A threshold breach in the rule engine must also produce its own alert.
    engine._maybe_create_alert(
        {"user_id": user_id, "name": "Test User"},
        _fake_assessment(user_id, engine.threshold + 10),
    )
    assert db.count_alerts() == alerts_before + 2, "rule-engine alert missing"
    return "alert + incident + audit, deduplicated"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _synthetic_user_days(user: str, days: int, spike_last: bool = False):
    rows = []
    for offset in range(days):
        spike = spike_last and offset == days - 1
        rows.append({
            "user": user,
            "day": pd.Timestamp("2026-01-01") + pd.Timedelta(days=offset),
            "logon_count": 40 if spike else 4,
            "unique_logon_pcs": 9 if spike else 1,
            "after_hours_logons": 25 if spike else 0,
            "device_events": 80 if spike else 3,
            "unique_device_pcs": 7 if spike else 1,
            "device_connects": 30 if spike else 1,
            "device_disconnects": 28 if spike else 1,
            "file_events": 900 if spike else 20,
            "unique_files": 700 if spike else 10,
            "unique_file_pcs": 6 if spike else 1,
        })
    return pd.DataFrame(rows)


def _insert_activity_days(user_id: int, days: int) -> None:
    """Insert a plausible run of Windows-style telemetry for one user."""
    from database import db_manager as db

    today = datetime.now()
    for offset in range(days, 0, -1):
        day = today - timedelta(days=offset)
        stamp = day.replace(hour=10, minute=0, second=0, microsecond=0)
        db.insert_activity({
            "user_id": user_id, "event_type": "unusual_login_time",
            "description": "Windows Security: logon event", "risk_points": 5.0,
            "login_hour": 10, "files_accessed": 4, "download_mb": 2.0,
            "usb_activity": 0, "privileged": 0, "data_transfer_mb": 0.0,
            "timestamp": stamp.isoformat(timespec="seconds"), "source": "eventlog",
        })
        for index in range(3):
            db.insert_activity({
                "user_id": user_id, "event_type": "normal_activity",
                "description": f"Write: report_{index}.docx (1,024 bytes)",
                "risk_points": 0.0, "login_hour": 10, "files_accessed": 1024,
                "download_mb": 0.0, "usb_activity": 0, "privileged": 0,
                "data_transfer_mb": 0.0,
                "timestamp": stamp.isoformat(timespec="seconds"),
                "source": "file_system",
            })


def _fake_assessment(user_id: int, score: float):
    from engine.risk_engine import RiskAssessment

    return RiskAssessment(
        user_id=user_id, risk_score=score, band="CRITICAL",
        explanation="synthetic breach for verification",
        contributing_events=[("privilege_escalation", score)],
    )


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-model", action="store_true",
                        help="skip the two checks that load the checkpoint")
    args = parser.parse_args()

    hint = _bootstrap.kev_env_hint()
    if hint:
        print(hint)
        print()

    print("Insider Threat Predictor — build verification")
    print("=" * 68)

    failures = 0
    for index, (label, func, required) in enumerate(RESULTS, start=1):
        skip = args.skip_model and label.startswith(("Kev checkpoint loads", "Kev inference"))
        if skip:
            print(f"[{index:2}] SKIP  {label}")
            continue
        try:
            detail = func()
            print(f"[{index:2}] PASS  {label}")
            if detail:
                print(f"          {detail}")
        except AssertionError as exc:
            if required:
                failures += 1
                print(f"[{index:2}] FAIL  {label}")
            else:
                print(f"[{index:2}] SKIP  {label}")
            print(f"          {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"[{index:2}] ERROR {label}")
            print(f"          {type(exc).__name__}: {exc}")
            traceback.print_exc()

    print("=" * 68)
    if failures:
        print(f"FAILED — {failures} check(s) did not pass.")
    else:
        print("OK — all checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
