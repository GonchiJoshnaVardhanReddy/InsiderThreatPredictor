"""Minimal end-to-end Kev smoke test.

Loads the checkpoint, builds a tiny synthetic user history, runs inference and
prints the probability and decision for each user-day. Exits 0 on success.

    <kev-env>\\Scripts\\python.exe scripts\\smoke_test_kev.py

Does not read the user's database and needs no CERT files.
"""

from __future__ import annotations

import sys
import time

import _bootstrap

_bootstrap.configure_console()

import pandas as pd  # noqa: E402

from ai import kev_anomaly_detector as kev  # noqa: E402
from ai import kev_feature_adapter as adapter  # noqa: E402
from config.settings import KEV_THRESHOLD  # noqa: E402

DAYS = 12


def synthetic_history() -> pd.DataFrame:
    """Two users with identical routine, differing only on the final day.

    The point is not to claim the model detects anything specific — it is to
    prove the pipeline runs and that a large behavioural shift produces a
    different number from a steady one.
    """
    rows = []
    for offset in range(DAYS):
        day = pd.Timestamp.today().normalize() - pd.Timedelta(days=DAYS - 1 - offset)
        steady = offset == DAYS - 1
        for user, spike in (("steady_user", False), ("shifted_user", steady)):
            rows.append({
                "user": user, "day": day,
                "logon_count": 60 if spike else 4,
                "unique_logon_pcs": 12 if spike else 1,
                "after_hours_logons": 40 if spike else 0,
                "device_events": 120 if spike else 3,
                "unique_device_pcs": 9 if spike else 1,
                "device_connects": 55 if spike else 1,
                "device_disconnects": 50 if spike else 1,
                "file_events": 1400 if spike else 20,
                "unique_files": 900 if spike else 10,
                "unique_file_pcs": 7 if spike else 1,
            })
    return pd.DataFrame(rows)


def main() -> int:
    print("Insider Threat Predictor — Kev smoke test")
    print("=" * 62)

    if not adapter.available():
        print(f"FAIL  {adapter.unavailable_reason()}")
        return 1

    detector = kev.detector()
    print(f"model     : {detector.model_reference()}")
    print(f"threshold : {KEV_THRESHOLD}")
    print(f"cuda      : {detector.cuda_available()} "
          f"({detector.gpu_name() or 'no GPU'})")

    started = time.time()
    if not detector.load():
        print(f"FAIL  model did not load: {detector.error()}")
        return 1
    print(f"loaded    : {detector.device()} in {time.time() - started:.1f}s")

    builder = adapter.load_feature_builder()
    prepared = builder.prepare_daily_features(synthetic_history())
    latest = prepared.groupby("user").tail(1)

    started = time.time()
    results = detector._score_frame(latest)
    elapsed = time.time() - started

    print(f"scored    : {len(results)} user-days in {elapsed:.2f}s")
    print("-" * 62)
    for result in sorted(results, key=lambda r: -r.probability):
        print(f"{result.user_name:14} p(true)={result.probability:.6f}  "
              f"baseline={result.baseline_anomaly_score:8.4f}  "
              f"history={result.baseline_history:2}  -> {result.label}")

    print("-" * 62)
    for result in results:
        if not 0.0 <= result.probability <= 1.0:
            print(f"FAIL  probability out of range: {result.probability}")
            return 1
        expected = "POTENTIAL_INSIDER_THREAT" if result.probability >= KEV_THRESHOLD else "NORMAL"
        if result.label != expected:
            print(f"FAIL  decision disagrees with the threshold for {result.user_name}")
            return 1

    if len(results) != 2:
        print(f"FAIL  expected 2 results, got {len(results)}")
        return 1

    print("OK — model loaded, inference ran, decisions match the threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
