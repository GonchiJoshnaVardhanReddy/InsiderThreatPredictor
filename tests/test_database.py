"""Tests for the SQLite database layer."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# --- Set up an isolated DB path for tests BEFORE importing db_manager --------
TEST_DIR = tempfile.mkdtemp(prefix="itp_tests_")
os.environ["ITP_TEST_DB"] = TEST_DIR

# Re-point the DB path before any module-level access.
import config.settings as settings
settings.DB_PATH = Path(TEST_DIR) / "test.db"
settings.SCHEMA_FILE = settings.DB_PATH  # unused, but keep the attribute
settings.MODELS_DIR = Path(TEST_DIR) / "models"
settings.REPORTS_DIR = Path(TEST_DIR) / "reports"
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from database import db_manager as db  # noqa: E402


class DatabaseTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db(seed=True)

    def test_tables_created(self) -> None:
        rows = db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'")
        names = {r["name"] for r in rows}
        for required in (
            "users", "activity_logs", "risk_history", "alerts",
            "incidents", "response_actions", "sentiment_history",
            "challenge_scores", "settings", "audit_log",
        ):
            self.assertIn(required, names)

    def test_seed_users(self) -> None:
        users = db.list_users()
        self.assertGreaterEqual(len(users), 5)
        first = users[0]
        self.assertIn("email", first)
        self.assertIn("department", first)

    def test_user_crud(self) -> None:
        new_id = db.add_user({
            "name": "Test User",
            "department": "Engineering",
            "role": "Software Engineer",
            "email": f"test-{datetime.now().timestamp()}@example.com",
            "baseline_login_hour": 9,
            "baseline_daily_downloads": 30,
            "baseline_file_access": 80,
        })
        self.assertGreater(new_id, 0)
        fetched = db.get_user(new_id)
        self.assertEqual(fetched["name"], "Test User")
        db.update_user(new_id, {
            "name": "Renamed",
            "department": "IT Security",
            "role": "Administrator",
            "email": fetched["email"],
            "baseline_login_hour": 8,
            "baseline_daily_downloads": 50,
            "baseline_file_access": 120,
            "account_status": "MONITORED",
        })
        updated = db.get_user(new_id)
        self.assertEqual(updated["name"], "Renamed")
        self.assertEqual(updated["department"], "IT Security")
        self.assertEqual(updated["account_status"], "MONITORED")
        db.delete_user(new_id)
        self.assertIsNone(db.get_user(new_id))

    def test_activity_storage(self) -> None:
        users = db.list_users()
        user_id = users[0]["user_id"]
        before = db.count_activity() if hasattr(db, "count_activity") else 0
        db.insert_activity({
            "user_id": user_id,
            "event_type": "failed_login",
            "description": "Test event",
            "risk_points": 8,
            "login_hour": 14,
            "files_accessed": 3,
            "download_mb": 0.0,
            "usb_activity": 0,
            "privileged": 0,
            "data_transfer_mb": 0.0,
            "timestamp": datetime.now().isoformat(),
        })
        after = db.count_activity()
        self.assertGreater(after, before)

    def test_alert_and_incident(self) -> None:
        users = db.list_users()
        user_id = users[0]["user_id"]
        incident_id = db.insert_incident(user_id, 33.0, "Test incident")
        alert_id = db.insert_alert(
            user_id=user_id,
            event_type="threshold_breach",
            risk_score=42.0,
            severity="MEDIUM",
            description="test",
            incident_id=incident_id,
        )
        self.assertGreater(alert_id, 0)
        db.resolve_alert(alert_id)
        updated = db.list_alerts()
        self.assertTrue(any(a["status"] == "RESOLVED" for a in updated))


if __name__ == "__main__":
    unittest.main()