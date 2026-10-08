"""Process monitor — uses `psutil` to detect new + terminated processes.

The first time a process is observed we record its PID and emit a
`privilege_escalation` event if it was launched with elevated rights on
Windows; otherwise we emit `normal_activity`. Termination events are
recorded quietly into the payload (they are also useful for forensics).
"""

from __future__ import annotations

import os
import time
from typing import Dict, Optional, Set

from monitor.base import BaseMonitor, MonitorEvent, map_event
from utils.helpers import log


POLL_INTERVAL: float = 1.5  # seconds between scans


class ProcessMonitor(BaseMonitor):
    """Polls `psutil.process_iter` to detect new/terminated processes."""

    def __init__(self, on_event=None) -> None:
        super().__init__(name="process_monitor", on_event=on_event)
        self._known_pids: Set[int] = set()
        self._first_scan = True

    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        try:
            import psutil
        except Exception as exc:
            raise RuntimeError(f"psutil unavailable: {exc}")
        # Seed with currently running PIDs to avoid a flood on first scan.
        try:
            self._known_pids = {p.pid for p in psutil.process_iter()}
        except Exception:  # pragma: no cover
            self._known_pids = set()
        self._psutil = psutil
        log.info("ProcessMonitor seeded with %d existing PIDs.", len(self._known_pids))

    def loop(self) -> None:
        try:
            current = {p.pid: p for p in self._psutil.process_iter()}
        except Exception as exc:  # pragma: no cover
            log.debug("ProcessMonitor scan failed: %s", exc)
            time.sleep(POLL_INTERVAL)
            return

        # Detect new processes.
        new_pids = set(current.keys()) - self._known_pids
        for pid in new_pids:
            proc = current.get(pid)
            if proc is None:
                continue
            self._emit_for_process(proc, is_new=True)
        # Detect terminated processes.
        terminated = self._known_pids - set(current.keys())
        for pid in terminated:
            self._emit_for_termination(pid)

        self._known_pids = set(current.keys())
        self._first_scan = False
        time.sleep(POLL_INTERVAL)

    # ------------------------------------------------------------------ #
    def _emit_for_process(self, proc, *, is_new: bool) -> None:
        try:
            name = proc.info.get("name") or proc.name() or "unknown"
            exe = proc.info.get("exe") or ""
            username = ""
            try:
                username = proc.info.get("username") or ""
            except Exception:
                username = ""
        except Exception:
            name = "unknown"
            exe = ""
            username = ""

        elevated = self._looks_elevated(username, exe)
        raw_kind = "privilege_escalation" if elevated else "normal_activity"
        mapped = map_event("process", raw_kind)
        if not mapped:
            return

        event = MonitorEvent(
            source="process",
            event_type=mapped["event_type"],
            description=f"Process started: {name} ({username or 'no user'})",
            risk_points=mapped["risk_points"],
            payload={"pid": proc.pid, "name": name, "username": username, "exe": exe},
        )
        self.emit(event)

    def _emit_for_termination(self, pid: int) -> None:
        event = MonitorEvent(
            source="process",
            event_type="normal_activity",
            description=f"Process terminated (pid={pid})",
            risk_points=0.0,
            payload={"pid": pid, "event": "terminated"},
        )
        self.emit(event)

    @staticmethod
    def _looks_elevated(username: str, exe: str) -> bool:
        """Heuristic — true only for clearly privileged processes."""
        if not username:
            return False
        lower_user = username.lower()
        if "system" in lower_user or "local service" in lower_user or "network service" in lower_user:
            return True
        # On Windows, processes started from System32 are typically privileged.
        if exe and "system32" in exe.lower():
            return True
        return False