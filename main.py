"""
Insider Threat Predictor — entry point.

Run with::

    python main.py
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path


# Make sure the project root is on sys.path so `import ai` etc. always work,
# even when the application is launched from a different working directory.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    """Bootstrap database, services and the GUI window."""
    try:
        from database import db_manager as db
        from ai import anomaly_detector
        from gui.app import Application
    except ImportError as exc:
        print("[fatal] Missing module:", exc, file=sys.stderr)
        print("Run `pip install -r requirements.txt` to install dependencies.",
              file=sys.stderr)
        return 2

    # 1. Make sure the SQLite database exists and is seeded.
    db.init_db(seed=True)

    # 2. Start loading the Kev checkpoint on a background thread. This is a
    #    no-op if it is already loaded, and it must not block: the checkpoint
    #    pulls a ~1.7 GB base model and builds a CUDA context. The GUI shows a
    #    "Kev loading…" state until it finishes. The model is never retrained.
    try:
        anomaly_detector.start_background_load()
    except Exception as exc:
        print(f"[warning] Could not start the Kev loader: {exc}", file=sys.stderr)

    # 3. Launch the GUI.
    app = Application()
    app.mainloop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # pragma: no cover - last-resort logging
        traceback.print_exc()
        sys.exit(1)