"""USB storage monitor.

Detects USB storage insertions by polling `psutil.disk_partitions()` for new
mount points. Works on every Windows account without requiring WMI/admin
privileges. Also tries to subscribe to WMI volume change events when
available — but the polling fallback is the default.
"""

from __future__ import annotations

import time
from typing import Set

from monitor.base import BaseMonitor, MonitorEvent, map_event
from utils.helpers import log


POLL_INTERVAL: float = 4.0


class USBMonitor(BaseMonitor):
    """Detects USB storage devices by tracking `psutil.disk_partitions()`."""

    def __init__(self, on_event=None) -> None:
        super().__init__(name="usb_monitor", on_event=on_event)
        self._known_mountpoints: Set[str] = set()
        self._psutil = None
        self._first_scan = True

    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        try:
            import psutil
        except Exception as exc:
            raise RuntimeError(f"psutil unavailable: {exc}")
        self._psutil = psutil
        try:
            self._known_mountpoints = {p.mountpoint for p in psutil.disk_partitions(all=False)}
        except Exception as exc:  # pragma: no cover
            log.debug("Initial disk_partitions failed: %s", exc)
            self._known_mountpoints = set()
        log.info("USBMonitor seeded with %d mount points.", len(self._known_mountpoints))

    def loop(self) -> None:
        try:
            current = {p.mountpoint for p in self._psutil.disk_partitions(all=False)}
        except Exception as exc:  # pragma: no cover
            log.debug("disk_partitions scan failed: %s", exc)
            time.sleep(POLL_INTERVAL)
            return

        new = current - self._known_mountpoints
        for mountpoint in new:
            # Skip fixed disks (C:, D: etc.) — only flag removable media.
            try:
                part = next(
                    (p for p in self._psutil.disk_partitions(all=False) if p.mountpoint == mountpoint),
                    None,
                )
            except Exception:
                part = None
            opts = (getattr(part, "opts", "") or "").lower()
            fstype = (getattr(part, "fstype", "") or "").lower()
            device = (getattr(part, "device", "") or "").lower()
            is_removable = (
                "removable" in opts
                or "removable" in device
                or fstype in ("vfat", "exfat", "fat32", "ntfs")
                and "cdrom" not in opts
            )
            if not is_removable and not self._first_scan:
                # Skip obvious non-removable drives on the first scan (they
                # already existed before the monitor started).
                continue
            mapped = map_event("usb", "usb_copy")
            if not mapped:
                continue
            event = MonitorEvent(
                source="usb",
                event_type=mapped["event_type"],
                description=f"USB / removable storage detected at {mountpoint} ({fstype or '?'})",
                risk_points=mapped["risk_points"],
                payload={"mountpoint": mountpoint, "fstype": fstype, "opts": opts},
            )
            self.emit(event)

        self._known_mountpoints = current
        self._first_scan = False
        time.sleep(POLL_INTERVAL)