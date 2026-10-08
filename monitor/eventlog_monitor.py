"""Windows Event Log monitor.

Tries to read the **Security** log first (rich auth events). If the running
account does not have permission, it transparently falls back to the
**Application** log which is readable by anyone. Non-Windows platforms fail
fast — the rest of the application keeps working.
"""

from __future__ import annotations

import time
from typing import Dict, List

from monitor.base import BaseMonitor, MonitorEvent, map_event
from utils.helpers import log


POLL_INTERVAL: float = 5.0

# Channel -> {event_id: raw_kind}
CHANNEL_EVENTS: Dict[str, Dict[str, str]] = {
    "Security": {
        "4625": "failed_login",
        "4624": "unusual_login_time",
        "4672": "privilege_escalation",
        "4720": "privilege_escalation",   # user account created
    },
    "Application": {
        # Windows Error Reporting entries often signal application crashes
        # (informational; surfaced as normal_activity).
    },
}


class WindowsEventLogMonitor(BaseMonitor):
    """Polls the Windows Event Log for security-relevant events."""

    def __init__(self, on_event=None) -> None:
        super().__init__(name="eventlog_monitor", on_event=on_event)
        self._win32evtlog = None
        self._win32evtlogutil = None
        self._active_channel: str = ""
        self._flags: int = 0

    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"pywin32 unavailable: {exc}")

        # Try Security first, then Application.
        for channel in ("Security", "Application"):
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
                win32evtlog.CloseEventLog(handle)
                self._active_channel = channel
                self._flags = flags
                log.info("EventLogMonitor using channel '%s'.", channel)
                break
            except Exception as exc:
                log.debug("Cannot open '%s' log: %s", channel, exc)
                continue
        if not self._active_channel:
            raise RuntimeError("No accessible Windows event log channel")

        self._win32evtlog = win32evtlog
        self._win32evtlogutil = win32evtlogutil

    def loop(self) -> None:
        try:
            handle = self._win32evtlog.OpenEventLog(None, self._active_channel)
        except Exception as exc:
            log.debug("Reopen log failed: %s", exc)
            time.sleep(POLL_INTERVAL)
            return

        try:
            try:
                events = self._win32evtlog.ReadEventLog(handle, self._flags, 0)
            except Exception as exc:
                log.debug("ReadEventLog failed: %s", exc)
                time.sleep(POLL_INTERVAL)
                return
            finally:
                try:
                    self._win32evtlog.CloseEventLog(handle)
                except Exception:  # pragma: no cover
                    pass

            if not events:
                time.sleep(POLL_INTERVAL)
                return

            channel_events = CHANNEL_EVENTS.get(self._active_channel, {})
            for ev_obj in events:
                event_id_raw = getattr(ev_obj, "EventID", 0)
                event_id = str(event_id_raw & 0xFFFF)  # strip high word
                raw_kind = channel_events.get(event_id)
                if not raw_kind:
                    continue
                mapped = map_event("eventlog", raw_kind)
                if not mapped:
                    continue
                try:
                    message = self._win32evtlogutil.SafeFormatMessage(ev_obj, self._active_channel)
                except Exception:
                    message = f"Event {event_id}"
                event = MonitorEvent(
                    source="eventlog",
                    event_type=mapped["event_type"],
                    description=message[:280],
                    risk_points=mapped["risk_points"],
                    payload={
                        "channel": self._active_channel,
                        "event_id": event_id,
                        "source_name": getattr(ev_obj, "SourceName", ""),
                        "computer": getattr(ev_obj, "ComputerName", ""),
                    },
                )
                self.emit(event)
        finally:
            time.sleep(POLL_INTERVAL)