"""
Base classes for the real Windows activity monitors.

A monitor is a long-running component that collects observations directly
from the operating system (file system, processes, network, USB, Event Log)
and translates them into `MonitorEvent` instances that share the same
schema as the demo data generator and the risk engine.

Each monitor runs in its own daemon thread so it never blocks the GUI.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional

from utils.helpers import iso_now, log


@dataclass
class MonitorEvent:
    """A single observation produced by any monitor."""

    source: str                       # file_pfs, process, network, usb, eventlog
    event_type: str                    # mapped to the same vocabulary as the risk engine
    description: str
    risk_points: float = 0.0
    user_id: Optional[int] = None     # resolved via session/user lookup
    payload: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=iso_now)


# Map monitor-specific events to the application's risk-engine vocabulary.
# This keeps the risk engine unchanged — it sees only the same eight event
# types it has always supported.
RISK_VOCAB: Dict[str, Dict[str, object]] = {
    "file_pfs": {
        "large_download":      ("Large file write detected",     10.0),
        "restricted_file_access": ("Write to a sensitive folder", 12.0),
        "normal_activity":     ("File system activity",           0.0),
    },
    "process": {
        "privilege_escalation": ("Process started with elevated rights", 18.0),
        "normal_activity":      ("Process started",                  0.0),
    },
    "network": {
        "bulk_data_transfer":   ("Large outbound transfer volume",   15.0),
        "normal_activity":      ("Network connection opened",         0.0),
    },
    "usb": {
        "usb_copy":             ("USB storage device connected",     15.0),
    },
    "eventlog": {
        "failed_login":         ("Windows Security: failed logon",    8.0),
        "unusual_login_time":   ("Windows Security: logon event",      5.0),
        "privilege_escalation": ("Windows Security: privilege use", 18.0),
    },
}


class BaseMonitor:
    """Subclass this to add a new OS-level data source."""

    def __init__(self, name: str, on_event: Optional[Callable[[MonitorEvent], None]] = None) -> None:
        self.name = name
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_error: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> bool:
        """Launch the monitor's background thread. Returns True on success."""
        if self._thread and self._thread.is_alive():
            return True
        self._stop_event.clear()
        try:
            self._thread = threading.Thread(
                target=self._run_safe, name=f"Monitor-{self.name}", daemon=True,
            )
            self._thread.start()
            log.info("Monitor '%s' started.", self.name)
            return True
        except Exception as exc:
            self._last_error = str(exc)
            log.exception("Could not start monitor '%s': %s", self.name, exc)
            return False

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the monitor thread to stop and wait briefly for it."""
        self._stop_event.set()
        try:
            self.shutdown()
        except Exception as exc:  # pragma: no cover
            log.debug("Monitor '%s' shutdown hook failed: %s", self.name, exc)
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> Dict:
        return {
            "name": self.name,
            "running": self.is_running(),
            "last_error": self._last_error,
        }

    # ------------------------------------------------------------------ #
    # Hooks for subclasses
    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        """Hook called once before the loop starts (open handles, etc.)."""

    def loop(self) -> None:
        """Repeated until `stop()` is called. Should sleep periodically."""

    def shutdown(self) -> None:
        """Hook called once on stop (close handles, etc.)."""

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _run_safe(self) -> None:
        try:
            self.setup()
        except Exception as exc:
            self._last_error = f"setup: {exc}"
            log.exception("Monitor '%s' setup failed: %s", self.name, exc)
            return
        while not self._stop_event.is_set():
            try:
                self.loop()
            except Exception as exc:  # pragma: no cover
                self._last_error = str(exc)
                log.exception("Monitor '%s' loop error: %s", self.name, exc)
                time.sleep(1.0)

    def emit(self, event: MonitorEvent) -> None:
        """Publish an observation to the engine callback."""
        if self._on_event is not None:
            try:
                self._on_event(event)
            except Exception as exc:  # pragma: no cover
                log.debug("Monitor callback error: %s", exc)

    def stop_requested(self) -> bool:
        return self._stop_event.is_set()


def map_event(source: str, raw_kind: str) -> Optional[Dict]:
    """Translate a raw monitor observation into the application's vocabulary.

    Returns a dict with `event_type`, `description` and `risk_points`,
    or `None` if the raw kind is unknown.
    """
    mapping = RISK_VOCAB.get(source, {})
    entry = mapping.get(raw_kind)
    if entry is None:
        # Unknown observation kinds are still forwarded as normal_activity
        # so they appear in the dashboard feed.
        entry = mapping.get("normal_activity")
        if entry is None:
            return None
    description, points = entry
    return {
        "event_type": raw_kind if raw_kind in mapping else "normal_activity",
        "description": description,
        "risk_points": float(points),
    }