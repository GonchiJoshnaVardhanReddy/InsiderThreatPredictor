"""Manager that owns every real monitor and dispatches them to the risk engine.

The Manager:
  * starts / stops the OS-level monitors on demand;
  * converts MonitorEvents into activity_logs rows;
  * asks the risk engine to recompute the user score whenever new activity arrives.
"""

from __future__ import annotations

import threading
from typing import Callable, Dict, List, Optional

from database import db_manager as db
from engine.risk_engine import RiskEngine
from monitor.base import BaseMonitor, MonitorEvent, map_event
from monitor.eventlog_monitor import WindowsEventLogMonitor
from monitor.file_monitor import FileSystemMonitor
from monitor.network_monitor import NetworkMonitor
from monitor.process_monitor import ProcessMonitor
from monitor.usb_monitor import USBMonitor
from utils.helpers import log


class MonitorManager:
    """Owns the real Windows monitors and persists their observations."""

    def __init__(self, risk_engine: RiskEngine,
                 on_event: Optional[Callable[[MonitorEvent], None]] = None) -> None:
        self.risk_engine = risk_engine
        self._on_event = on_event
        self._monitors: Dict[str, BaseMonitor] = {}
        self._lock = threading.Lock()

        callback = self._handle_event

        file_mon = FileSystemMonitor(on_event=callback)
        process_mon = ProcessMonitor(on_event=callback)
        network_mon = NetworkMonitor(on_event=callback)
        usb_mon = USBMonitor(on_event=callback)
        event_mon = WindowsEventLogMonitor(on_event=callback)

        self._monitors = {
            file_mon.name:    file_mon,
            process_mon.name: process_mon,
            network_mon.name: network_mon,
            usb_mon.name:     usb_mon,
            event_mon.name:     event_mon,
        }

    # ------------------------------------------------------------------ #
    def monitors(self) -> List[BaseMonitor]:
        return list(self._monitors.values())

    def status(self) -> List[Dict]:
        return [m.status() for m in self._monitors.values()]

    def names(self) -> List[str]:
        return list(self._monitors.keys())

    def start_all(self) -> Dict[str, bool]:
        """Start every monitor that supports this environment."""
        out: Dict[str, bool] = {}
        with self._lock:
            for name, monitor in self._monitors.items():
                try:
                    ok = monitor.start()
                except Exception as exc:  # pragma: no cover
                    ok = False
                    log.warning("Monitor %s failed to start: %s", name, exc)
                out[name] = ok
        return out

    def stop_all(self) -> None:
        with self._lock:
            for monitor in self._monitors.values():
                try:
                    monitor.stop()
                except Exception as exc:  # pragma: no cover
                    log.debug("Monitor stop failed: %s", exc)

    def start(self, name: str) -> bool:
        monitor = self._monitors.get(name)
        if not monitor:
            return False
        return monitor.start()

    def stop(self, name: str) -> None:
        monitor = self._monitors.get(name)
        if monitor:
            monitor.stop()

    def is_running(self, name: str) -> bool:
        monitor = self._monitors.get(name)
        return bool(monitor and monitor.is_running())

    # ------------------------------------------------------------------ #
    # Internal — translate monitor events into activity log rows.
    # ------------------------------------------------------------------ #
    def _handle_event(self, event: MonitorEvent) -> None:
        try:
            # 1. Persist the observation (attributed to the first seeded user for
            #    the demo). In a real deployment you would map the OS user to a
            #    known application user via your directory service.
            user_id = self._resolve_user_id()
            row = {
                "user_id": user_id,
                "event_type": event.event_type,
                "description": event.description,
                "risk_points": event.risk_points,
                "login_hour": None,
                "files_accessed": event.payload.get("size", 0) or 0,
                "download_mb": round((event.payload.get("size", 0) or 0) / 1024 / 1024, 2),
                "usb_activity": 1 if event.source == "usb" else 0,
                "privileged": 1 if event.event_type == "privilege_escalation" else 0,
                "data_transfer_mb": 0.0,
                "timestamp": event.timestamp,
                "source": event.source,
            }
            db.insert_activity(row)

            # 2. Recompute the rule-based risk for the affected user only.
            #    Scoring every user on every event was O(events x users) and is
            #    the reason the UI stalled under load.
            try:
                self.risk_engine.assess_user_and_persist(user_id)
            except Exception as exc:  # pragma: no cover
                log.debug("Risk recompute failed: %s", exc)

            # 3. Notify GUI listeners.
            if self._on_event:
                try:
                    self._on_event(event)
                except Exception:  # pragma: no cover
                    pass
        except Exception as exc:  # pragma: no cover
            log.exception("MonitorManager.handle_event failed: %s", exc)

    @staticmethod
    def _resolve_user_id() -> int:
        """Pick the user that owns this observation.

        The shipped demo accounts are fictional, so the monitor manager maps
        every observation to the FIRST user in the database. A production
        deployment should replace this with a Windows user -> employee lookup.
        """
        users = db.list_users()
        if not users:
            db.init_db(seed=True)
            users = db.list_users()
        return int(users[0]["user_id"]) if users else 0