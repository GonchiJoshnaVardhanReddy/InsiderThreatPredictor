"""File-system monitor built on top of `watchdog`.

Watches one or more paths (default: user profile + Desktop + Downloads) and
emits a MonitorEvent for every write/create. Files larger than 50 MB are
classified as `large_download`, writes to a configurable sensitive folder
list are `restricted_file_access`, everything else is `normal_activity`.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import List, Optional

from monitor.base import BaseMonitor, MonitorEvent, map_event
from utils.helpers import log


# Paths that should be treated as restricted for the running account.
# Beginners can edit this list in their config later.
DEFAULT_RESTRICTED_PATTERNS: List[str] = [
    "Windows", "Program Files", "Program Files (x86)", "AppData", ".ssh",
    "credentials", "secrets", "private", "confidential",
]

LARGE_FILE_BYTES: int = 50 * 1024 * 1024  # 50 MB


def _is_restricted(path: str, patterns: List[str]) -> bool:
    lowered = path.lower()
    return any(p.lower() in lowered for p in patterns)


class _WatchdogHandler:
    """Adapter that turns watchdog events into MonitorEvents."""

    def __init__(self, monitor: "FileSystemMonitor") -> None:
        self._monitor = monitor

    def dispatch(self, event) -> None:  # pragma: no cover - threaded callback
        from watchdog.events import FileSystemEvent

        if not isinstance(event, FileSystemEvent):
            return
        if event.is_directory:
            return
        if event.event_type not in ("created", "modified", "moved"):
            return
        path = event.dest_path if event.event_type == "moved" else event.src_path
        self._monitor._on_fs_event(path, event.event_type)


class FileSystemMonitor(BaseMonitor):
    """Writes file-system events from watchdog into the activity log."""

    def __init__(
        self,
        watch_paths: Optional[List[str]] = None,
        restricted_patterns: Optional[List[str]] = None,
        on_event=None,
    ) -> None:
        super().__init__(name="file_system", on_event=on_event)
        user_profile = os.environ.get("USERPROFILE", str(Path.home()))
        candidates = watch_paths or [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Downloads"),
        ]
        self.watch_paths: List[str] = [p for p in candidates if os.path.isdir(p)]
        self.restricted_patterns = restricted_patterns or DEFAULT_RESTRICTED_PATTERNS
        self._observer = None
        self._handler = None

    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        try:
            from watchdog.observers import Observer
        except Exception as exc:
            raise RuntimeError(f"watchdog unavailable: {exc}")
        if not self.watch_paths:
            raise RuntimeError("No watchable paths exist on this system.")
        self._handler = _WatchdogHandler(self)
        self._observer = Observer()
        for path in self.watch_paths:
            self._observer.schedule(self._handler.dispatch, path, recursive=False)
        self._observer.start()
        log.info("FileSystemMonitor watching: %s", ", ".join(self.watch_paths))

    def shutdown(self) -> None:
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception:  # pragma: no cover
                pass
            self._observer = None

    def loop(self) -> None:
        # watchdog callbacks do the real lifting; we just sleep until stopped.
        import time
        time.sleep(0.5)

    # ------------------------------------------------------------------ #
    def _on_fs_event(self, path: str, kind: str) -> None:
        try:
            size = 0
            if os.path.exists(path):
                size = os.path.getsize(path)
        except OSError:
            size = 0

        if _is_restricted(path, self.restricted_patterns):
            raw_kind = "restricted_file_access"
        elif size >= LARGE_FILE_BYTES:
            raw_kind = "large_download"
        else:
            raw_kind = "normal_activity"

        mapped = map_event("file_pfs", raw_kind)
        if not mapped:
            return

        event = MonitorEvent(
            source="file_system",
            event_type=mapped["event_type"],
            description=f"{kind.title()}: {os.path.basename(path)} ({size:,} bytes)",
            risk_points=mapped["risk_points"],
            user_id=None,
            payload={"path": path, "size": size, "kind": kind},
        )
        self.emit(event)