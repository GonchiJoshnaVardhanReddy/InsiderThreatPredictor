"""Tests for the AI detector facade.

The primary detector is Kev, which needs a GPU and a multi-gigabyte checkpoint,
so the tests here cover the facade's contract and the optional legacy
IsolationForest detector. Loading the real checkpoint is the job of
`scripts/verify_build.py` and `scripts/smoke_test_kev.py`.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

TEST_DIR = tempfile.mkdtemp(prefix="itp_ml_tests_")
import config.settings as settings
settings.DB_PATH = Path(TEST_DIR) / "ml.db"
settings.MODELS_DIR = Path(TEST_DIR) / "models"
settings.REPORTS_DIR = Path(TEST_DIR) / "reports"
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from ai import anomaly_detector, model_training  # noqa: E402
from config.settings import KEV_THRESHOLD  # noqa: E402
from database import db_manager as db  # noqa: E402


class KevFacadeTests(unittest.TestCase):
    """The Kev contract, without loading the checkpoint."""

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db(seed=True)

    def test_status_vocabulary(self) -> None:
        self.assertIn(
            anomaly_detector.status(),
            {"not_loaded", "loading", "loaded", "error"},
        )

    def test_default_threshold_is_published_value(self) -> None:
        # No override has been written in this database yet.
        self.assertAlmostEqual(anomaly_detector.threshold(), KEV_THRESHOLD, places=12)

    def test_threshold_override_is_honoured(self) -> None:
        db.set_setting("kev_threshold", "0.5")
        try:
            self.assertAlmostEqual(anomaly_detector.threshold(), 0.5)
        finally:
            db.set_setting("kev_threshold", repr(KEV_THRESHOLD))
        self.assertAlmostEqual(anomaly_detector.threshold(), KEV_THRESHOLD, places=12)

    def test_bad_override_falls_back(self) -> None:
        db.set_setting("kev_threshold", "not-a-number")
        try:
            self.assertAlmostEqual(anomaly_detector.threshold(), KEV_THRESHOLD, places=12)
        finally:
            db.set_setting("kev_threshold", repr(KEV_THRESHOLD))

    def test_predict_for_unknown_user_is_empty(self) -> None:
        self.assertIsNone(anomaly_detector.predict_for_user(99999))

    def test_predict_for_all_is_a_list(self) -> None:
        self.assertIsInstance(anomaly_detector.predict_for_all(), list)

    def test_summary_describes_the_model(self) -> None:
        summary = anomaly_detector.summary()
        for key in ("model", "threshold", "analyzed_users", "threat_count",
                    "normal_count", "coverage"):
            self.assertIn(key, summary)
        self.assertEqual(len(summary["coverage"]), 10)

    def test_model_is_never_retrained_at_startup(self) -> None:
        # The facade must not expose a retrain entry point for Kev.
        self.assertFalse(hasattr(anomaly_detector, "train"))


class LegacyDetectorTests(unittest.TestCase):
    """The optional IsolationForest detector — skipped when sklearn is absent."""

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db(seed=True)
        try:
            anomaly_detector.legacy_train()
        except Exception as exc:
            print(f"[skip] legacy training failed: {exc}")

    def setUp(self) -> None:
        if not anomaly_detector.legacy_available():
            self.skipTest("scikit-learn unavailable")

    def test_model_persisted(self) -> None:
        self.assertTrue(settings.MODEL_FILE.exists())

    def test_predict_returns_rows_per_user(self) -> None:
        users = db.list_users()
        results = anomaly_detector.legacy_predict_for_all()
        self.assertEqual(len(results), len(users))
        for row in results:
            self.assertIn("user_name", row)
            self.assertIn("anomaly_score", row)
            self.assertIn("is_anomaly", row)
            self.assertIn("top_factors", row)
            self.assertIsInstance(row["top_factors"], list)

    def test_retrain_overwrites_model(self) -> None:
        meta = anomaly_detector.legacy_train()
        self.assertIn("trained_at", meta)
        self.assertTrue(settings.MODEL_FILE.exists())

    def test_feature_columns_match(self) -> None:
        from config.settings import FEATURE_COLUMNS
        frame = model_training.features_dataframe()
        self.assertEqual(list(frame.columns), FEATURE_COLUMNS)


if __name__ == "__main__":
    unittest.main()
