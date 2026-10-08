"""Real Windows activity monitors.

This package collects activity directly from the operating system:

* file system events (watchdog)
* process start/stop (psutil)
* network connections (psutil)
* USB device insertion (WMI on Windows)
* Windows Security Event Log (pywin32)

The monitors are independent threads, so they do not block the GUI. Every
observation is converted into a row in the `activity_logs` table using the
same schema as the rest of the application — the risk engine treats them
identically, whether they originated from a real monitor or the optional
demo data generator.
"""

from monitor.base import BaseMonitor, MonitorEvent
from monitor.monitor_manager import MonitorManager

__all__ = ["BaseMonitor", "MonitorEvent", "MonitorManager"]