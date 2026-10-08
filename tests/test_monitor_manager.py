"""Tests for the real OS monitor manager."""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

TEST_DIR = tempfile.mkdtemp(prefix="itp_mon_tests_")
import config.settings as settings
settings.DB_PATH = Path(TEST_DIR) / "mon.db"
settings.MODELS_DIR = Path(TEST_DIR) / "models"
settings.REPORTS_DIR = Path(TEST_DIR) / "reports"
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from database import db_manager as db  # noqa: E402
from engine.risk_engine import RiskEngine  # noqa: E402
from monitor.monitor_manager import MonitorManager  # noqa: E402
from monitor.base import RISK_VOCAB  # noqa: E402


class MonitorManagerTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db(seed=True)
        cls.engine = RiskEngine()
        cls.received: list = []

        def cb(event):
            cls.received.append(event)

        cls.manager = MonitorManager(risk_engine=cls.engine, on_event=cb)

    def test_all_monitor_names(self) -> None:
        names = self.manager.names()
        self.assertIn("file_system", names)
        self.assertIn("process_monitor", names)
        self.assertIn("network_monitor", names)
        self.assertIn("usb_monitor", names)
        self.assertIn("eventlog_monitor", names)

    def test_status_before_start(self) -> None:
        for entry in self.manager.status():
            self.assertFalse(entry["running"])

    def test_start_stop_lifecycle(self) -> None:
        # Try to start every monitor. Some will not start because the test
        # environment lacks WMI/admin. That must be a graceful failure, not an
        # exception.
        results = self.manager.start_all()
        self.assertEqual(set(results.keys()), set(self.manager.names()))
        time.sleep(0.5)
        for name, ok in results.items():
            self.assertIsInstance(ok, bool)
        self.manager.stop_all()
        for entry in self.manager.status():
            self.assertFalse(entry["running"], f"{entry['name']} should be stopped")

    def test_risk_vocabulary_is_consistent(self) -> None:
        # Every event_type the engine recognises must appear in the
        # vocabulary map of at least one monitor.
        engine_types = set(self.engine.weights.keys())
        vocab_types = set()
        for mapping in RISK_VOCAB.values():
            vocab_types.update(mapping.keys())
        self.assertTrue(engine_types.issubset(vocab_types),
                        f"Engine types missing from vocabulary: {engine_types - vocab_types}")


if __name__ == "__main__":
    unittest.main()