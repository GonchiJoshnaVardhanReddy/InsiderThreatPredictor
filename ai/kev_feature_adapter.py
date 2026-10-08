"""
Domain adaptation layer: Windows telemetry -> Kev's CERT-style user-day rows.

WHY THIS EXISTS
---------------
Kev v3 was trained on CERT r4.2 *daily user behaviour summaries* — one row per
employee per day, with ten counts describing logons, device (removable media)
activity and file activity. This application collects *Windows event rows*:
each row is one observation from one monitor (a file write, a USB arrival, a
Security event-log entry), and many rows share a day.

Those are not the same thing. Feeding Windows rows straight into Kev would
produce garbage, and pretending the two schemas are identical would be worse
than useless because it would look plausible. So this module does the honest
work: it aggregates event rows into user-day rows and maps them onto Kev's ten
features, marking for each feature whether the mapping is faithful, a proxy, or
degenerate on a single-machine deployment.

WHAT THIS IS NOT
----------------
This is a **prototype adapter**, not a retrained model. Kev's weights were not
changed. Where Windows telemetry cannot faithfully reconstruct a CERT feature,
the closest defensible mapping is used and documented in `FEATURE_COVERAGE`,
and the per-result coverage flags are surfaced in the UI so nobody mistakes a
proxy for a measurement. See README "Kev behavioural model" for the caveats.

The baseline/deviation maths is NOT reimplemented here — it is delegated to
`feature_builder.prepare_daily_features()` from the Kev source checkout, which
is the same code path the model was trained and validated with.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from config.settings import KEV_REPO_CANDIDATES, KEV_REPO_PATH
from database import db_manager as db
from utils.helpers import log


# Mirrors feature_builder.BASE_FEATURES. Kept as a local constant so this module
# can build the daily table before the Kev checkout is on sys.path; the two are
# checked for agreement in load_feature_builder().
BASE_FEATURE_NAMES: List[str] = [
    "logon_count",
    "unique_logon_pcs",
    "after_hours_logons",
    "device_events",
    "unique_device_pcs",
    "device_connects",
    "device_disconnects",
    "file_events",
    "unique_files",
    "unique_file_pcs",
]


# --------------------------------------------------------------------------- #
# Event classification
# --------------------------------------------------------------------------- #
# The ten CERT base features and how each row of Windows telemetry can
# contribute to them. Classification uses `event_type` (semantic) and falls
# back to `source` (which collector wrote the row), so it keeps working for
# rows written before the `source` column existed.
FILE_EVENT_TYPES = frozenset(
    {"large_download", "bulk_data_transfer", "restricted_file_access"}
)
LOGON_EVENT_TYPES = frozenset({"unusual_login_time"})
DEVICE_EVENT_TYPES = frozenset({"usb_copy"})

WORK_DAY_START_HOUR = 8
WORK_DAY_END_HOUR = 18


# --------------------------------------------------------------------------- #
# Coverage documentation
# --------------------------------------------------------------------------- #
# verdict is one of:
#   "direct"     - Windows telemetry carries this quantity as-is
#   "proxy"      - a defensible stand-in, but not the same measurement
#   "degenerate" - cannot vary on a single-machine deployment
#   "absent"     - no Windows counterpart; the feature stays 0
FEATURE_COVERAGE: List[Dict[str, str]] = [
    {
        "feature": "logon_count",
        "verdict": "proxy",
        "source": "eventlog rows with event_type=unusual_login_time",
        "notes": "Windows does not emit a logon census to this app; only logons "
                 "surfaced by the Security event log are counted, so this "
                 "systematically undercounts versus CERT.",
    },
    {
        "feature": "unique_logon_pcs",
        "verdict": "degenerate",
        "source": "1 when any logon was observed that day, else 0",
        "notes": "The app runs on one host and does not record source "
                 "workstation per logon. CERT saw many PCs per user.",
    },
    {
        "feature": "after_hours_logons",
        "verdict": "proxy",
        "source": "logon rows whose login_hour falls outside 08:00-18:00",
        "notes": "Only as complete as logon_count above; inherits its undercount.",
    },
    {
        "feature": "device_events",
        "verdict": "direct",
        "source": "rows with event_type=usb_copy or source=usb",
        "notes": "The USB monitor reports removable-media arrivals directly.",
    },
    {
        "feature": "unique_device_pcs",
        "verdict": "degenerate",
        "source": "1 when any device event was seen that day, else 0",
        "notes": "Single host; cannot exceed 1 as it did in CERT.",
    },
    {
        "feature": "device_connects",
        "verdict": "proxy",
        "source": "same rows as device_events",
        "notes": "The monitor reports device arrival, not a separate connect / "
                 "disconnect pair, so disconnects are not observable.",
    },
    {
        "feature": "device_disconnects",
        "verdict": "absent",
        "source": "always 0",
        "notes": "No Windows counterpart is collected by this app.",
    },
    {
        "feature": "file_events",
        "verdict": "proxy",
        "source": "rows with event_type in the file set, or source=file_system",
        "notes": "Counts file-write observations the monitor surfaced, which is "
                 "a sample of file activity rather than CERT's full audit trail.",
    },
    {
        "feature": "unique_files",
        "verdict": "proxy",
        "source": "distinct row descriptions among file rows that day",
        "notes": "Descriptions embed the file name, so this approximates "
                 "distinct-file counts without persisting file paths.",
    },
    {
        "feature": "unique_file_pcs",
        "verdict": "degenerate",
        "source": "1 when any file event was seen that day, else 0",
        "notes": "Single host; cannot exceed 1 as it did in CERT.",
    },
]


def coverage_for(feature: str) -> Dict[str, str]:
    for entry in FEATURE_COVERAGE:
        if entry["feature"] == feature:
            return dict(entry)
    return {"feature": feature, "verdict": "absent", "source": "unknown", "notes": ""}


# --------------------------------------------------------------------------- #
# feature_builder import (lives in the Kev checkout, not in the app)
# --------------------------------------------------------------------------- #
_feature_builder = None
_feature_builder_error: Optional[str] = None


def resolve_repo_path() -> Optional[Path]:
    """Locate the Kev source checkout that contains feature_builder.py."""
    candidates: List[Path] = []
    if KEV_REPO_PATH:
        candidates.append(Path(KEV_REPO_PATH))
    candidates.extend(Path(p) for p in KEV_REPO_CANDIDATES)
    for candidate in candidates:
        try:
            if (candidate / "feature_builder.py").is_file():
                return candidate
        except OSError:
            continue
    return None


def load_feature_builder():
    """Import feature_builder from the Kev checkout, or raise with a reason.

    The module is not installable (it sits at the repository root rather than
    inside the `kev` package), so it is imported by putting that root on
    sys.path, which is what the reference `kev_detector.py` does too.
    """
    global _feature_builder, _feature_builder_error
    if _feature_builder is not None:
        return _feature_builder
    if _feature_builder_error is not None:
        raise RuntimeError(_feature_builder_error)

    repo = resolve_repo_path()
    if repo is None:
        _feature_builder_error = (
            "Could not find the Kev source checkout containing feature_builder.py. "
            "Set KEV_REPO_PATH to the directory that holds it."
        )
        raise RuntimeError(_feature_builder_error)

    path_str = str(repo)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    try:
        module = importlib.import_module("feature_builder")
        # Guard against a same-named module being picked up elsewhere.
        if not hasattr(module, "prepare_daily_features"):
            raise ImportError(
                f"feature_builder at {path_str} has no prepare_daily_features()"
            )
        remote = list(getattr(module, "BASE_FEATURES", []))
        if remote and remote != BASE_FEATURE_NAMES:
            raise ImportError(
                "feature_builder.BASE_FEATURES does not match the feature list "
                f"this adapter maps onto: {remote}"
            )
    except Exception as exc:
        _feature_builder_error = f"Could not import feature_builder from {path_str}: {exc}"
        raise RuntimeError(_feature_builder_error) from exc

    _feature_builder = module
    log.info("Kev feature_builder loaded from %s", path_str)
    return module


def available() -> bool:
    """True when the feature builder can be imported."""
    try:
        load_feature_builder()
        return True
    except Exception:
        return False


def unavailable_reason() -> Optional[str]:
    try:
        load_feature_builder()
        return None
    except Exception as exc:
        return str(exc)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def _load_activity(user_ids: Optional[List[int]] = None) -> pd.DataFrame:
    """Read activity_logs into a frame, one row per event."""
    where = ""
    params: List = []
    if user_ids:
        placeholders = ",".join("?" for _ in user_ids)
        where = f"WHERE a.user_id IN ({placeholders})"
        params = list(user_ids)

    rows = db.fetch_all(
        f"""SELECT a.user_id, a.event_type, a.description, a.login_hour,
                   a.timestamp, a.source, u.name AS user_name
            FROM activity_logs a
            LEFT JOIN users u USING(user_id)
            {where}
            ORDER BY a.timestamp""",
        tuple(params),
    )
    if not rows:
        return pd.DataFrame(
            columns=["user_id", "user_name", "event_type", "description",
                     "login_hour", "timestamp", "source"]
        )
    frame = pd.DataFrame(db.rows_to_dicts(rows))
    # Tolerate rows written before the source column existed.
    if "source" not in frame.columns:
        frame["source"] = None
    return frame


def build_daily_table(user_ids: Optional[List[int]] = None) -> pd.DataFrame:
    """Aggregate activity rows into one row per user per day.

    Returns a frame with `user`, `day` and Kev's ten base features. Users with
    no recorded activity produce no row at all — nothing is invented for them.
    """
    events = _load_activity(user_ids)
    if events.empty:
        return pd.DataFrame(columns=["user", "user_id", "day", *BASE_FEATURE_NAMES])

    events = events.copy()
    # format="mixed": rows written before iso_now() emitted the ISO-8601 "T"
    # separator carry a space instead. Without this pandas infers the format
    # from the first row and coerces every other one to NaT — which silently
    # dropped every simulated row from the behavioural model.
    events["timestamp"] = pd.to_datetime(
        events["timestamp"], format="mixed", errors="coerce"
    )
    events = events.dropna(subset=["timestamp"])
    if events.empty:
        return pd.DataFrame(columns=["user", "user_id", "day", *BASE_FEATURE_NAMES])

    events["day"] = events["timestamp"].dt.normalize()
    events["event_type"] = events["event_type"].fillna("").astype(str)
    events["source"] = events["source"].fillna("").astype(str)
    events["description"] = events["description"].fillna("").astype(str)

    is_logon = events["event_type"].isin(LOGON_EVENT_TYPES)
    is_device = events["event_type"].isin(DEVICE_EVENT_TYPES) | events["source"].eq("usb")
    is_file = events["event_type"].isin(FILE_EVENT_TYPES) | events["source"].eq("file_system")

    hour = pd.to_numeric(events["login_hour"], errors="coerce")
    is_after_hours = is_logon & hour.notna() & (
        (hour < WORK_DAY_START_HOUR) | (hour >= WORK_DAY_END_HOUR)
    )

    events["_logon"] = is_logon.astype("int64")
    events["_after_hours"] = is_after_hours.astype("int64")
    events["_device"] = is_device.astype("int64")
    events["_file"] = is_file.astype("int64")
    # Only file rows contribute to the distinct-file proxy.
    events["_file_desc"] = events["description"].where(is_file)

    grouped = events.groupby(["user_id", "day"], as_index=False).agg(
        user_name=("user_name", "first"),
        logon_count=("_logon", "sum"),
        after_hours_logons=("_after_hours", "sum"),
        device_events=("_device", "sum"),
        file_events=("_file", "sum"),
        unique_files=("_file_desc", "nunique"),
    )

    # Single-host degeneracy: these cannot exceed 1 on one machine.
    grouped["unique_logon_pcs"] = (grouped["logon_count"] > 0).astype("int64")
    grouped["unique_device_pcs"] = (grouped["device_events"] > 0).astype("int64")
    grouped["unique_file_pcs"] = (grouped["file_events"] > 0).astype("int64")
    # The USB monitor reports arrivals, not a connect/disconnect pair.
    grouped["device_connects"] = grouped["device_events"]
    grouped["device_disconnects"] = 0

    grouped["user"] = grouped["user_name"].fillna(
        grouped["user_id"].map(lambda uid: f"user_{uid}")
    )
    grouped = grouped.rename(columns={"user_name": "user_label"})
    grouped = grouped.sort_values(["user", "day"]).reset_index(drop=True)

    ordered = ["user", "user_id", "user_label", "day", *BASE_FEATURE_NAMES]
    return grouped[[c for c in ordered if c in grouped.columns]]


def build_scoring_rows(
    user_ids: Optional[List[int]] = None,
    history_limit: int = 40,
) -> pd.DataFrame:
    """Build the user-day table and run it through Kev's own feature builder.

    Returns the augmented frame (baseline_history, baseline_anomaly_score and
    the ten `*_rel_dev` columns added by `feature_builder.prepare_daily_features`).
    """
    daily = build_daily_table(user_ids)
    if daily.empty:
        return daily

    builder = load_feature_builder()

    # feature_builder needs 30 prior observations to build a baseline and 10
    # before it produces one at all. Trim to a window that comfortably covers
    # the rolling median so scoring does not read the entire history.
    if history_limit:
        daily = daily.sort_values(["user", "day"]).groupby("user").tail(history_limit)

    missing = [c for c in ("user", "day", *BASE_FEATURE_NAMES) if c not in daily.columns]
    if missing:
        # Tolerate a partially populated table rather than crashing the GUI.
        log.debug("Daily table missing columns %s; skipping Kev feature build.", missing)
        return daily

    return builder.prepare_daily_features(daily.reset_index(drop=True))


def coverage_summary() -> List[Dict[str, str]]:
    """Coverage documentation for display in the UI."""
    return [dict(entry) for entry in FEATURE_COVERAGE]


def coverage_for_result(row: pd.Series) -> Dict[str, str]:
    """Per-feature coverage flags for one scored user-day."""
    out: Dict[str, str] = {}
    for name in BASE_FEATURE_NAMES:
        entry = coverage_for(name)
        verdict = entry["verdict"]
        # A degenerate feature that is actually non-zero, or an "absent" one
        # that somehow has data, is reported as the mapping's real strength.
        if verdict in ("degenerate", "absent") and float(row.get(name, 0) or 0) > 0:
            verdict = "observed"
        out[name] = verdict
    return out
