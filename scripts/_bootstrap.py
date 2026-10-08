"""Small shared bootstrap for the scripts in this folder.

Puts the project root on sys.path and (optionally) redirects the database to a
throwaway file so a verification run can never touch the user's live data.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def use_temp_database() -> Path:
    """Point the database layer at a temp file and return its path.

    Must be called before anything opens a connection. The real
    insider_threat.db is never touched by the verification scripts.
    """
    from database import db_manager as db

    temp_dir = Path(tempfile.mkdtemp(prefix="itp_verify_"))
    path = temp_dir / "verify.db"
    db.DB_PATH = path
    return path


def configure_console() -> None:
    """Avoid UnicodeEncodeError on legacy Windows consoles (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover
            pass


def kev_env_hint() -> Optional[str]:
    """Return a hint string when torch is missing from this interpreter."""
    try:
        import torch  # noqa: F401
        return None
    except Exception:
        return (
            "PyTorch is not installed for this interpreter. Run the scripts with "
            "the interpreter that has the Kev environment, e.g.\n"
            "  <kev-env>\\Scripts\\python.exe scripts\\verify_build.py"
        )
