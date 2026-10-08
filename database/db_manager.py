"""
Database manager — handles all SQLite access for the application.

Only this module should talk to SQLite directly. Other modules call into the
methods exposed here so the SQL stays in one place.
"""

from __future__ import annotations

import random
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from config.settings import (
    ACCOUNT_STATUSES,
    DB_PATH,
    DEPARTMENTS,
    DEFAULT_RISK_THRESHOLD,
    ROLES,
)
from utils.helpers import iso_now, log


SCHEMA_FILE: Path = Path(__file__).with_name("schema.sql")


# --------------------------------------------------------------------- #
# Connection helper
# --------------------------------------------------------------------- #
def _connect() -> sqlite3.Connection:
    """Return a new SQLite connection with foreign keys turned on."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn():
    """Context manager that yields a connection and ensures it is closed."""
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------- #
# Initialisation
# --------------------------------------------------------------------- #
def init_db(seed: bool = True) -> None:
    """Create tables (if missing) and optionally seed demo data."""
    log.info("Initialising database at %s", DB_PATH)
    with get_conn() as conn:
        schema_sql = SCHEMA_FILE.read_text(encoding="utf-8")
        conn.executescript(schema_sql)

        # Migration: activity_logs.source was added after the first release, so
        # databases created earlier are missing it. CREATE TABLE IF NOT EXISTS
        # will not add it, hence this one-off ALTER.
        columns = {r[1] for r in conn.execute("PRAGMA table_info(activity_logs)")}
        if "source" not in columns:
            conn.execute("ALTER TABLE activity_logs ADD COLUMN source TEXT")
            log.info("Migrated activity_logs: added 'source' column.")

        # Store default settings the first time we boot up.
        existing = conn.execute(
            "SELECT value FROM settings WHERE key = 'risk_threshold'"
        ).fetchone()
        if not existing:
            _store_setting(conn, "risk_threshold", str(DEFAULT_RISK_THRESHOLD))
        existing_interval = conn.execute(
            "SELECT value FROM settings WHERE key = 'sim_interval_ms'"
        ).fetchone()
        if not existing_interval:
            _store_setting(conn, "sim_interval_ms", "1500")
        existing_weights = conn.execute(
            "SELECT value FROM settings WHERE key = 'risk_weights'"
        ).fetchone()
        if not existing_weights:
            from config.settings import DEFAULT_RISK_WEIGHTS

            import json

            _store_setting(conn, "risk_weights", json.dumps(DEFAULT_RISK_WEIGHTS))

        if seed and conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            _seed_demo_users(conn)


def _store_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        (key, value),
    )


def _seed_demo_users(conn: sqlite3.Connection) -> None:
    """Populate the users table with fictional employees."""
    log.info("Seeding demo users…")
    demo_employees = [
        ("Alice Johnson",   "Engineering", "Software Engineer", "alice.johnson@example.com", 9,  40, 120),
        ("Bob Williams",    "Finance",     "Analyst",           "bob.williams@example.com",   10, 30,  90),
        ("Carol Davis",     "Human Resources", "Manager",       "carol.davis@example.com",    8,  20,  60),
        ("David Miller",    "Sales",       "Senior Engineer",   "david.miller@example.com",  11, 50, 100),
        ("Eve Thompson",    "IT Security", "Administrator",     "eve.thompson@example.com",   7,  35,  80),
        ("Frank Garcia",    "Research",    "Analyst",           "frank.garcia@example.com",   9,  25,  70),
        ("Grace Lee",       "Operations",  "Manager",           "grace.lee@example.com",      8,  18,  55),
        ("Henry Wilson",    "Engineering", "Intern",            "henry.wilson@example.com",  10,  60, 130),
        ("Isabel Martinez", "Finance",     "Director",          "isabel.martinez@example.com", 9,  45, 110),
        ("Jack Robinson",   "IT Security", "Senior Engineer",   "jack.robinson@example.com",   8,  40, 100),
    ]
    now = iso_now()
    for name, dept, role, email, base_h, base_dl, base_fa in demo_employees:
        conn.execute(
            """
            INSERT INTO users (name, department, role, email,
                               baseline_login_hour, baseline_daily_downloads,
                               baseline_file_access, risk_score,
                               account_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE', ?)
            """,
            (name, dept, role, email, base_h, base_dl, base_fa, now),
        )
    log.info("Seeded %d demo users.", len(demo_employees))


# --------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------- #
def fetch_all(query: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
    with get_conn() as conn:
        cur = conn.execute(query, params)
        return cur.fetchall()


def fetch_one(query: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        cur = conn.execute(query, params)
        return cur.fetchone()


def execute(query: str, params: Sequence[Any] = ()) -> int:
    """Run a write statement and return the lastrowid (or rowcount)."""
    with get_conn() as conn:
        cur = conn.execute(query, params)
        return cur.lastrowid or cur.rowcount


def executemany(query: str, params: Iterable[Sequence[Any]]) -> int:
    with get_conn() as conn:
        cur = conn.executemany(query, params)
        return cur.rowcount


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]


# --------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------- #
def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    row = fetch_one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def all_settings() -> Dict[str, str]:
    rows = fetch_all("SELECT key, value FROM settings")
    return {r["key"]: r["value"] for r in rows}


# --------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------- #
def list_users() -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all("SELECT * FROM users ORDER BY name")
    )


def get_user(user_id: int) -> Optional[Dict[str, Any]]:
    row = fetch_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
    return dict(row) if row else None


def add_user(data: Dict[str, Any]) -> int:
    now = iso_now()
    return execute(
        """
        INSERT INTO users (name, department, role, email,
                           baseline_login_hour, baseline_daily_downloads,
                           baseline_file_access, risk_score, account_status,
                           created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            data["name"],
            data["department"],
            data["role"],
            data["email"],
            int(data.get("baseline_login_hour", 9)),
            int(data.get("baseline_daily_downloads", 30)),
            int(data.get("baseline_file_access", 80)),
            data.get("account_status", "ACTIVE"),
            now,
        ),
    )


def update_user(user_id: int, data: Dict[str, Any]) -> None:
    execute(
        """
        UPDATE users
        SET name = ?, department = ?, role = ?, email = ?,
            baseline_login_hour = ?, baseline_daily_downloads = ?,
            baseline_file_access = ?, account_status = ?
        WHERE user_id = ?
        """,
        (
            data["name"],
            data["department"],
            data["role"],
            data["email"],
            int(data.get("baseline_login_hour", 9)),
            int(data.get("baseline_daily_downloads", 30)),
            int(data.get("baseline_file_access", 80)),
            data.get("account_status", "ACTIVE"),
            user_id,
        ),
    )


def delete_user(user_id: int) -> None:
    execute("DELETE FROM users WHERE user_id = ?", (user_id,))


def update_user_risk(user_id: int, risk_score: float, status: Optional[str] = None) -> None:
    if status:
        execute(
            "UPDATE users SET risk_score = ?, account_status = ? WHERE user_id = ?",
            (risk_score, status),
        )
    else:
        execute(
            "UPDATE users SET risk_score = ? WHERE user_id = ?",
            (risk_score, user_id),
        )


def set_user_status(user_id: int, status: str) -> None:
    if status not in ACCOUNT_STATUSES:
        raise ValueError(f"Unknown status {status}")
    execute(
        "UPDATE users SET account_status = ? WHERE user_id = ?",
        (status, user_id),
    )


def count_users() -> Dict[str, int]:
    rows = fetch_all(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN account_status = 'ACTIVE' THEN 1 ELSE 0 END) AS active, "
        "SUM(CASE WHEN risk_score >= 50 THEN 1 ELSE 0 END) AS high_risk "
        "FROM users"
    )
    row = rows[0] if rows else None
    if not row:
        return {"total": 0, "active": 0, "high_risk": 0}
    return {
        "total": int(row["total"] or 0),
        "active": int(row["active"] or 0),
        "high_risk": int(row["high_risk"] or 0),
    }


# --------------------------------------------------------------------- #
# Activity logs
# --------------------------------------------------------------------- #
def insert_activity(event: Dict[str, Any]) -> int:
    return execute(
        """INSERT INTO activity_logs
           (user_id, event_type, description, risk_points,
            login_hour, files_accessed, download_mb, usb_activity,
            privileged, data_transfer_mb, timestamp, source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event["user_id"],
            event["event_type"],
            event.get("description", ""),
            float(event.get("risk_points", 0)),
            event.get("login_hour"),
            event.get("files_accessed", 0),
            event.get("download_mb", 0.0),
            event.get("usb_activity", 0),
            event.get("privileged", 0),
            event.get("data_transfer_mb", 0.0),
            event.get("timestamp", iso_now()),
            event.get("source"),
        ),
    )


def recent_activity(limit: int = 50) -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all(
            """SELECT a.*, u.name AS user_name
               FROM activity_logs a LEFT JOIN users u USING(user_id)
               ORDER BY a.timestamp DESC LIMIT ?""",
            (limit,),
        )
    )


def activity_for_user(user_id: int, since_iso: Optional[str] = None,
                      limit: Optional[int] = None) -> List[Dict[str, Any]]:
    if since_iso is None:
        rows = fetch_all(
            """SELECT * FROM activity_logs
               WHERE user_id = ? ORDER BY timestamp DESC""",
            (user_id,),
        )
    else:
        rows = fetch_all(
            """SELECT * FROM activity_logs
               WHERE user_id = ? AND timestamp >= ?
               ORDER BY timestamp DESC""",
            (user_id, since_iso),
        )
    if limit:
        rows = rows[:limit]
    return rows_to_dicts(rows)


def count_activity() -> int:
    row = fetch_one("SELECT COUNT(*) AS c FROM activity_logs")
    return int(row["c"] if row else 0)


def activity_per_day(days: int = 7) -> List[Tuple[str, int]]:
    """Return (date_str, count) for the most recent `days` days."""
    rows = fetch_all(
        """SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS c
           FROM activity_logs
           GROUP BY day
           ORDER BY day DESC""",
    )
    # Most recent first.
    return [(r["day"], int(r["c"])) for r in rows][:days][::-1]


# --------------------------------------------------------------------- #
# Risk history
# --------------------------------------------------------------------- #
def insert_risk_history(user_id: int, score: float, explanation: str) -> None:
    execute(
        "INSERT INTO risk_history (user_id, risk_score, explanation, timestamp) "
        "VALUES (?, ?, ?, ?)",
        (user_id, score, explanation, iso_now()),
    )


def latest_risk_history(limit: int = 100) -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all(
            """SELECT h.*, u.name AS user_name
               FROM risk_history h LEFT JOIN users u USING(user_id)
               ORDER BY h.timestamp DESC LIMIT ?""",
            (limit,),
        )
    )


# --------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------- #
def insert_alert(
    user_id: int,
    event_type: str,
    risk_score: float,
    severity: str,
    description: str,
    incident_id: Optional[int] = None,
) -> int:
    return execute(
        """INSERT INTO alerts
           (user_id, event_type, risk_score, severity, status,
            incident_id, description, created_at)
           VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?)""",
        (user_id, event_type, risk_score, severity, incident_id,
         description, iso_now()),
    )


def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    query_sql = (
        "SELECT a.*, u.name AS user_name FROM alerts a "
        "LEFT JOIN users u USING(user_id) WHERE 1=1"
    )
    params: List[Any] = []
    if severity and severity != "ALL":
        query_sql += " AND a.severity = ?"
        params.append(severity)
    if status and status != "ALL":
        query_sql += " AND a.status = ?"
        params.append(status)
    if search:
        query_sql += " AND (u.name LIKE ? OR a.event_type LIKE ? OR a.description LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])
    query_sql += " ORDER BY a.created_at DESC"
    return rows_to_dicts(fetch_all(query_sql, params))


def acknowledge_alert(alert_id: int) -> None:
    execute(
        "UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_at = ? "
        "WHERE alert_id = ?",
        (iso_now(), alert_id),
    )


def resolve_alert(alert_id: int) -> None:
    execute(
        "UPDATE alerts SET status = 'RESOLVED', resolved_at = ? "
        "WHERE alert_id = ?",
        (iso_now(), alert_id),
    )


def count_alerts() -> int:
    row = fetch_one("SELECT COUNT(*) AS c FROM alerts")
    return int(row["c"] if row else 0)


def has_open_alert(user_id: int, event_type: str) -> bool:
    """True when this user already has an OPEN alert of the given type.

    Used to deduplicate detector alerts so a user who stays above a threshold
    does not collect one alert per scoring pass.
    """
    row = fetch_one(
        "SELECT 1 FROM alerts WHERE user_id = ? AND event_type = ? "
        "AND status = 'OPEN' LIMIT 1",
        (user_id, event_type),
    )
    return row is not None


def alerts_per_severity() -> Dict[str, int]:
    rows = fetch_all("SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity")
    out = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in rows:
        out[r["severity"]] = int(r["c"])
    return out


# --------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------- #
def insert_incident(user_id: int, trigger_score: float, summary: str) -> int:
    now = iso_now()
    return execute(
        """INSERT INTO incidents
           (user_id, trigger_score, status, summary, created_at, updated_at)
           VALUES (?, ?, 'OPEN', ?, ?, ?)""",
        (user_id, trigger_score, summary, now, now),
    )


def update_incident_status(incident_id: int, status: str) -> None:
    execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
        (status, iso_now(), incident_id),
    )


def link_alert_to_incident(alert_id: int, incident_id: int) -> None:
    execute(
        "UPDATE alerts SET incident_id = ? WHERE alert_id = ?",
        (incident_id, alert_id),
    )


def list_incidents(status: Optional[str] = None) -> List[Dict[str, Any]]:
    if status and status != "ALL":
        rows = fetch_all(
            """SELECT i.*, u.name AS user_name FROM incidents i
               LEFT JOIN users u USING(user_id) WHERE i.status = ?
               ORDER BY i.created_at DESC""",
            (status,),
        )
    else:
        rows = fetch_all(
            """SELECT i.*, u.name AS user_name FROM incidents i
               LEFT JOIN users u USING(user_id) ORDER BY i.created_at DESC"""
        )
    return rows_to_dicts(rows)


def get_incident(incident_id: int) -> Optional[Dict[str, Any]]:
    row = fetch_one(
        """SELECT i.*, u.name AS user_name FROM incidents i
           LEFT JOIN users u USING(user_id) WHERE incident_id = ?""",
        (incident_id,),
    )
    return dict(row) if row else None


# --------------------------------------------------------------------- #
# Response actions / audit log
# --------------------------------------------------------------------- #
def log_response_action(
    incident_id: int, user_id: int, action_type: str,
    performed_by: str, details: str,
) -> int:
    return execute(
        """INSERT INTO response_actions
           (incident_id, user_id, action_type, performed_by, details, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (incident_id, user_id, action_type, performed_by, details, iso_now()),
    )


def list_response_actions(incident_id: Optional[int] = None) -> List[Dict[str, Any]]:
    if incident_id:
        rows = fetch_all(
            """SELECT r.*, u.name AS user_name FROM response_actions r
               LEFT JOIN users u USING(user_id)
               WHERE r.incident_id = ? ORDER BY r.timestamp DESC""",
            (incident_id,),
        )
    else:
        rows = fetch_all(
            """SELECT r.*, u.name AS user_name FROM response_actions r
               LEFT JOIN users u USING(user_id)
               ORDER BY r.timestamp DESC"""
        )
    return rows_to_dicts(rows)


def audit(actor: str, action: str, details: str = "") -> None:
    execute(
        "INSERT INTO audit_log (actor, action, details, timestamp) VALUES (?, ?, ?, ?)",
        (actor, action, details, iso_now()),
    )


def list_audit(limit: int = 200) -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
    )


# --------------------------------------------------------------------- #
# Sentiment
# --------------------------------------------------------------------- #
def insert_sentiment(text: str, scores: Dict[str, float], label: str) -> int:
    return execute(
        """INSERT INTO sentiment_history
           (text, compound, positive, neutral, negative, label, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            text,
            float(scores["compound"]),
            float(scores["pos"]),
            float(scores["neu"]),
            float(scores["neg"]),
            label,
            iso_now(),
        ),
    )


def list_sentiment(limit: int = 50) -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all(
            "SELECT * FROM sentiment_history ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
    )


# --------------------------------------------------------------------- #
# Gamification
# --------------------------------------------------------------------- #
def insert_challenge_score(participant: str, challenge: str,
                           score: int, correct: int, total: int) -> int:
    return execute(
        """INSERT INTO challenge_scores
           (participant, challenge, score, correct, total, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (participant, challenge, score, correct, total, iso_now()),
    )


def leaderboard(limit: int = 10) -> List[Dict[str, Any]]:
    return rows_to_dicts(
        fetch_all(
            """SELECT participant, SUM(score) AS total_score,
                      SUM(correct) AS total_correct,
                      SUM(total) AS total_questions,
                      COUNT(*) AS attempts,
                      MAX(timestamp) AS last_attempt
               FROM challenge_scores
               GROUP BY participant
               ORDER BY total_score DESC LIMIT ?""",
            (limit,),
        )
    )


def reset_demo_data() -> None:
    """Delete every row from the dynamic tables but keep schema and settings."""
    with get_conn() as conn:
        for table in (
            "response_actions",
            "challenge_scores",
            "sentiment_history",
            "alerts",
            "incidents",
            "risk_history",
            "activity_logs",
            "audit_log",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.execute("UPDATE users SET risk_score = 0, account_status = 'ACTIVE'")
    log.info("Demo data has been reset.")