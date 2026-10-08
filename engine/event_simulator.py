"""
Demo data generator — synthesises fictional employee activity.

This module is INTENTIONALLY labelled "demo data generator". It exists for
ONE reason only: when a SOC analyst is showcasing the Insider Threat
Predictor on a machine that does not generate real OS events (for instance a
demo laptop or a classroom PC), they can switch on the demo generator to
populate the activity feed with plausible-looking synthetic events.

In a production deployment this generator is **not** the primary data
source — real observations come from the `monitor` package (file system,
processes, network, USB, Windows Event Log). The demo generator and the
real monitors write into the exact same `activity_logs` table so the rest
of the system does not know (or care) which one created a row.

The generator schedules the next tick using Tkinter `after()`, so the GUI
remains responsive.
"""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, List, Optional

from config.settings import DEFAULT_SIM_INTERVAL_MS
from database import db_manager as db
from utils.helpers import iso_now, log, weighted_rnd_choice


# Probability weights for each demo event type. Higher value => more frequent.
# Kept independent from the risk weights so demo behaviour can be tuned.
EVENT_PROBABILITIES: dict = {
    "normal_activity": 50,
    "unusual_login_time": 6,
    "failed_login": 7,
    "large_download": 6,
    "usb_copy": 4,
    "restricted_file_access": 5,
    "bulk_data_transfer": 4,
    "privilege_escalation": 3,
}

EVENT_DESCRIPTIONS: dict = {
    "normal_activity":         "Routine browsing and file access during work hours.",
    "unusual_login_time":      "Login outside the user's normal baseline hour.",
    "failed_login":            "Multiple failed login attempts detected.",
    "large_download":          "Downloaded a large file from the corporate share.",
    "usb_copy":                "USB device connected — files copied to removable media.",
    "restricted_file_access":  "Attempted access to a restricted file share.",
    "bulk_data_transfer":      "High-volume data transfer to an external destination.",
    "privilege_escalation":    "Privilege escalation attempt detected.",
}


@dataclass
class SimulatedEvent:
    user_id: int
    user_name: str
    event_type: str
    description: str
    risk_points: float
    login_hour: Optional[int]
    files_accessed: int
    download_mb: float
    usb_activity: int
    privileged: int
    data_transfer_mb: float
    timestamp: str

    def to_db_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "event_type": self.event_type,
            "description": self.description,
            "risk_points": self.risk_points,
            "login_hour": self.login_hour,
            "files_accessed": self.files_accessed,
            "download_mb": self.download_mb,
            "usb_activity": self.usb_activity,
            "privileged": self.privileged,
            "data_transfer_mb": self.data_transfer_mb,
            "timestamp": self.timestamp,
            "source": "demo",
        }


def activity_scale(user: dict) -> float:
    """Stable per-user activity multiplier, demo only.

    Gives each fictional employee a different working volume so the users do
    not all look identical to the behavioural model.
    """
    uid = int(user.get("user_id", 1))
    return 0.5 + ((uid * 37) % 21) / 10.0


def _event_payload(event_type: str, user: dict, scale: float = 1.0) -> dict:
    """Build the numeric fields that accompany each event type."""
    login_hour = datetime.now().hour
    files_accessed = max(1, int(random.randint(1, 12) * scale))
    download_mb = 0.0
    usb_activity = 0
    privileged = 0
    data_transfer_mb = 0.0

    baseline_hour = int(user.get("baseline_login_hour", 9))

    if event_type == "unusual_login_time":
        candidate_hours = [h for h in range(0, 24) if abs(h - baseline_hour) >= 4]
        login_hour = random.choice(candidate_hours or [baseline_hour])

    elif event_type == "failed_login":
        pass

    elif event_type == "large_download":
        download_mb = round(random.uniform(120.0, 900.0) * scale, 2)

    elif event_type == "usb_copy":
        usb_activity = 1
        download_mb = round(random.uniform(50.0, 400.0) * scale, 2)
        data_transfer_mb = download_mb

    elif event_type == "restricted_file_access":
        files_accessed = max(1, int(random.randint(5, 30) * scale))

    elif event_type == "bulk_data_transfer":
        data_transfer_mb = round(random.uniform(500.0, 2500.0) * scale, 2)
        download_mb = data_transfer_mb

    elif event_type == "privilege_escalation":
        privileged = 1
        files_accessed = max(1, int(random.randint(3, 15) * scale))

    return {
        "login_hour": login_hour,
        "files_accessed": files_accessed,
        "download_mb": download_mb,
        "usb_activity": usb_activity,
        "privileged": privileged,
        "data_transfer_mb": data_transfer_mb,
    }


def generate_event(risk_weights: dict, users: Optional[List[dict]] = None,
                   user: Optional[dict] = None, scale: float = 1.0
                   ) -> Optional[SimulatedEvent]:
    """Generate a single demo event and persist it."""
    if users is None:
        users = db.list_users()
    if not users:
        log.warning("No users available; cannot generate demo event.")
        return None

    if user is None:
        user = random.choice(users)
    event_type = weighted_rnd_choice(EVENT_PROBABILITIES)
    payload = _event_payload(event_type, user, scale)
    risk_points = float(risk_weights.get(event_type, 0))

    event = SimulatedEvent(
        user_id=user["user_id"],
        user_name=user["name"],
        event_type=event_type,
        description=EVENT_DESCRIPTIONS.get(event_type, ""),
        risk_points=risk_points,
        login_hour=payload["login_hour"],
        files_accessed=payload["files_accessed"],
        download_mb=payload["download_mb"],
        usb_activity=payload["usb_activity"],
        privileged=payload["privileged"],
        data_transfer_mb=payload["data_transfer_mb"],
        timestamp=iso_now(),
    )
    db.insert_activity(event.to_db_dict())
    return event


class EventSimulator:
    """
    Schedules demo-event generation using Tkinter `after()`.

    Kept under the name `EventSimulator` (and exposed as `demo_generator`
    in `engine/__init__.py`) to avoid breaking other imports. Every single
    place that uses it must describe it as the **demo data generator**.
    """

    # Episode scheduling (demo only): every EPISODE_EVERY ticks, one user
    # enters an amplified-activity episode lasting EPISODE_LENGTH ticks.
    EPISODE_EVERY: int = 25
    EPISODE_LENGTH: int = 12
    EPISODE_SCALE: float = 3.5

    def __init__(self, risk_weights: dict,
                 interval_ms: int = DEFAULT_SIM_INTERVAL_MS,
                 on_event: Optional[Callable[[SimulatedEvent], None]] = None) -> None:
        self.risk_weights = dict(risk_weights)
        self.interval_ms = interval_ms
        self._scheduler = None
        self._after_id: Optional[str] = None
        self._lock = threading.Lock()
        self._running = False
        self.on_event = on_event
        self._ticks = 0
        self._episode_user: Optional[int] = None
        self._episode_ticks = 0

    # --------------------------------------------------------------- #
    def update_weights(self, weights: dict) -> None:
        self.risk_weights = dict(weights)

    def update_interval(self, interval_ms: int) -> None:
        self.interval_ms = max(100, int(interval_ms))

    # --------------------------------------------------------------- #
    def is_running(self) -> bool:
        return self._running

    def start(self, scheduler) -> None:
        with self._lock:
            if self._running:
                return
            self._scheduler = scheduler
            self._running = True
            self._schedule_next()
            log.info("Demo data generator started (%d ms interval).", self.interval_ms)

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            if self._scheduler and self._after_id is not None:
                try:
                    self._scheduler.after_cancel(self._after_id)
                except Exception:
                    pass
            self._after_id = None
            log.info("Demo data generator stopped.")

    # --------------------------------------------------------------- #
    def _schedule_next(self) -> None:
        if not self._running or self._scheduler is None:
            return
        self._after_id = self._scheduler.after(self.interval_ms, self._tick)

    def _tick(self) -> None:
        if not self._running:
            return
        try:
            users = db.list_users()
            user, scale = self._pick_target(users)
            event = generate_event(self.risk_weights, users=users,
                                   user=user, scale=scale)
            if event and self.on_event is not None:
                self.on_event(event)
        except Exception as exc:  # pragma: no cover
            log.exception("Demo generator tick failed: %s", exc)
        self._schedule_next()

    def _pick_target(self, users: List[dict]):
        """Choose which demo user acts this tick, and how loudly.

        Mostly ordinary activity, but periodically one user enters a short
        "episode" of amplified activity. That is what makes the demo exercise
        the behavioural pipeline: a user's volumes move, their feature
        deviations move, and their risk signal moves with them. Demo only —
        nothing here influences the rule weights or the model.
        """
        if not users:
            return None, 1.0

        self._ticks += 1
        if self._episode_user is None and self._ticks % self.EPISODE_EVERY == 0:
            self._episode_user = random.choice(users)["user_id"]
            self._episode_ticks = self.EPISODE_LENGTH
            log.info("Demo episode started for user %s.", self._episode_user)

        if self._episode_user is not None:
            self._episode_ticks -= 1
            if self._episode_ticks <= 0:
                self._episode_user = None
            else:
                target = next(
                    (u for u in users if u["user_id"] == self._episode_user), None
                )
                if target is not None:
                    return target, self.EPISODE_SCALE

        user = random.choice(users)
        return user, activity_scale(user)


# Convenient alias used in module-level docstrings & GUI labels.
DemoGenerator = EventSimulator


# --------------------------------------------------------------------------- #
# Demo history seeding
# --------------------------------------------------------------------------- #
DEMO_HISTORY_DAYS: int = 16


def history_days_available() -> int:
    """How many distinct days of activity the database currently holds."""
    row = db.fetch_one(
        "SELECT COUNT(DISTINCT substr(timestamp, 1, 10)) AS days FROM activity_logs"
    )
    return int(row["days"] if row else 0)


def seed_demo_history(days: int = DEMO_HISTORY_DAYS) -> int:
    """Backfill synthetic past activity so the behavioural model has a baseline.

    Kev v3 compares each day against that user's own recent history: it needs
    at least 10 prior observations before it produces any deviation at all, and
    30 before the baseline is fully populated. A fresh demo database has only
    today, so without this the behavioural layer would show every user as
    perfectly normal forever.

    These rows are **synthetic demo data**, written with source='demo_seed' so
    they are always distinguishable from real telemetry. Only call this when
    demo mode is switched on.
    """
    users = db.list_users()
    if not users:
        return 0

    today = datetime.now().date()
    rows = []
    for user in users:
        scale = activity_scale(user)
        for offset in range(days, 0, -1):
            day = today - timedelta(days=offset)
            # A deterministic weekly rhythm plus noise, so each user has a
            # believable baseline instead of a flat line.
            weekday = day.weekday()
            volume = scale * (0.6 if weekday >= 5 else 1.0)
            events_that_day = max(1, int(random.uniform(3, 9) * volume))
            for _ in range(events_that_day):
                hour = random.randint(8, 18)
                stamp = datetime(
                    day.year, day.month, day.day,
                    hour, random.randint(0, 59), random.randint(0, 59),
                ).isoformat(timespec="seconds")
                rows.append({
                    "user_id": user["user_id"],
                    "event_type": "normal_activity",
                    "description": "Demo history: routine activity.",
                    "risk_points": 0.0,
                    "login_hour": hour,
                    "files_accessed": max(1, int(random.randint(1, 12) * volume)),
                    "download_mb": 0.0,
                    "usb_activity": 0,
                    "privileged": 0,
                    "data_transfer_mb": 0.0,
                    "timestamp": stamp,
                    "source": "demo_seed",
                })

    for row in rows:
        db.insert_activity(row)
    log.info("Seeded %d demo history rows across %d users.", len(rows), len(users))
    db.audit("demo_generator", "demo_history_seeded",
             f"rows={len(rows)} days={days} users={len(users)}")
    return len(rows)