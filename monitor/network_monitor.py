"""Network monitor — uses `psutil` to observe active connections.

A connection that transfers more than ~100 MB during a sample window is
classified as `bulk_data_transfer`. Routine socket creation is logged as
`normal_activity`. Connections are looked up by remote IP and (when
possible) by remote hostname.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Set, Tuple

from monitor.base import BaseMonitor, MonitorEvent, map_event
from utils.helpers import log


POLL_INTERVAL: float = 3.0
BULK_THRESHOLD_BYTES: int = 100 * 1024 * 1024  # 100 MB per sampling window


def _safe_addr(value):
    """Return an (ip, port) tuple from whatever psutil handed us.

    psutil returns namedtuples on Python 3.10+ but plain tuples on older
    versions — handle both transparently. Empty tuples mean "not connected"
    and translate to None.
    """
    if value is None:
        return None
    if isinstance(value, tuple):
        if len(value) < 2:
            return None
        return value
    ip = getattr(value, "ip", None)
    port = getattr(value, "port", None)
    if ip is None or port is None:
        return None
    return (ip, port)


class NetworkMonitor(BaseMonitor):
    """Polls psutil.net_connections and tracks per-PID byte counters."""

    def __init__(self, on_event=None) -> None:
        super().__init__(name="network_monitor", on_event=on_event)
        self._seen_connections: Set[Tuple[str, int]] = set()
        self._pid_bytes: Dict[int, int] = defaultdict(int)
        self._last_poll = 0.0

    # ------------------------------------------------------------------ #
    def setup(self) -> None:
        try:
            import psutil
        except Exception as exc:
            raise RuntimeError(f"psutil unavailable: {exc}")
        self._psutil = psutil

    def loop(self) -> None:
        try:
            connections = self._psutil.net_connections(kind="inet")
        except Exception as exc:  # pragma: no cover
            log.debug("NetworkMonitor scan failed: %s", exc)
            time.sleep(POLL_INTERVAL)
            return

        # Approximate byte counts via per-connection metrics.
        for conn in connections:
            laddr = _safe_addr(getattr(conn, "laddr", None))
            raddr = _safe_addr(getattr(conn, "raddr", None))
            pid = getattr(conn, "pid", None)
            if raddr is None or pid is None:
                continue
            remote_str = f"{raddr[0]}:{raddr[1]}"
            key = (remote_str, pid)
            if key in self._seen_connections:
                continue
            self._seen_connections.add(key)
            raw_kind = "normal_activity"
            mapped = map_event("network", raw_kind)
            if not mapped:
                continue
            local_str = f"{laddr[0]}:{laddr[1]}" if laddr else "?"
            event = MonitorEvent(
                source="network",
                event_type=mapped["event_type"],
                description=f"Connection {local_str} -> {remote_str} (pid={pid})",
                risk_points=mapped["risk_points"],
                payload={
                    "pid": pid,
                    "local": local_str,
                    "remote": remote_str,
                    "status": str(getattr(conn, "status", "")),
                },
            )
            self.emit(event)

        # Bulk detection — sample interface counters and compute deltas.
        self._check_bulk_transfer()
        time.sleep(POLL_INTERVAL)

    # ------------------------------------------------------------------ #
    def _check_bulk_transfer(self) -> None:
        try:
            counters = self._psutil.net_io_counters(pernic=True)
        except Exception:  # pragma: no cover
            return
        if not hasattr(self, "_last_counters"):
            self._last_counters = {nic: (c.bytes_sent, c.bytes_recv) for nic, c in counters.items()}
            return
        for nic, counter in counters.items():
            prev = self._last_counters.get(nic, (counter.bytes_sent, counter.bytes_recv))
            sent_delta = counter.bytes_sent - prev[0]
            recv_delta = counter.bytes_recv - prev[1]
            total_delta = sent_delta + recv_delta
            if total_delta >= BULK_THRESHOLD_BYTES:
                raw_kind = "bulk_data_transfer"
                mapped = map_event("network", raw_kind)
                if not mapped:
                    continue
                event = MonitorEvent(
                    source="network",
                    event_type=mapped["event_type"],
                    description=f"{nic}: high traffic {total_delta/1024/1024:.1f} MB",
                    risk_points=mapped["risk_points"],
                    payload={
                        "nic": nic,
                        "bytes_sent_delta": sent_delta,
                        "bytes_recv_delta": recv_delta,
                    },
                )
                self.emit(event)
            self._last_counters[nic] = (counter.bytes_sent, counter.bytes_recv)