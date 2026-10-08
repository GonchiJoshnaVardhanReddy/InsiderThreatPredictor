"""Smoke test for the real OS monitor manager."""

import sys
import time

sys.path.insert(0, ".")

from engine.risk_engine import load_engine
from monitor.monitor_manager import MonitorManager

engine = load_engine()
mgr = MonitorManager(risk_engine=engine, on_event=None)
results = mgr.start_all()
print("Real monitor start results:")
for name, ok in results.items():
    label_text = "OK LIVE" if ok else "unavailable"
    print(f"  {name:18s} -> {label_text}")
time.sleep(2.5)
status = {s["name"]: s for s in mgr.status()}
print()
print("After 2.5s:")
for name, s in status.items():
    err = s["last_error"] or "-"
    print(f"  {name:18s} running={s['running']} err={err}")
mgr.stop_all()