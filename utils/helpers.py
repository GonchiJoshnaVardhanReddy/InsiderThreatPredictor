"""
Common helper functions used across the project.

These helpers are intentionally simple so a beginner Python learner can read them
without needing advanced language features.
"""

from __future__ import annotations

import logging
import os
import random
from datetime import datetime, timedelta
from typing import Any, Iterable, List, Tuple

# -------- Logging --------------------------------------------------------
# A single global logger keeps things simple.
LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("insider_threat")

# Loading the Kev checkpoint makes the Hugging Face client emit an INFO line
# for every HTTP HEAD it performs. That is dozens of lines of noise in the GUI
# console for an operation that either succeeds quietly or raises.
for _noisy in ("httpx", "httpcore", "huggingface_hub", "urllib3", "filelock"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


# -------- Time helpers ---------------------------------------------------
def now() -> datetime:
    """Return the current local time (timezone naive for SQLite friendliness)."""
    return datetime.now()


def fmt_dt(value: datetime | None) -> str:
    """Format a datetime for display in the GUI."""
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def iso_now() -> str:
    """ISO-8601 representation of now().

    Sep is "T", not a space: the space form is not ISO-8601, and a column
    mixing the two made `pd.to_datetime` coerce the space-form rows to NaT.
    """
    return now().isoformat(sep="T", timespec="seconds")


def minutes_between(start: datetime, end: datetime) -> float:
    """Number of minutes between two datetimes (positive)."""
    return abs((end - start).total_seconds()) / 60.0


# -------- Numeric helpers -----------------------------------------------
def clamp(value: float, low: float, high: float) -> float:
    """Clamp a number between a low and high bound."""
    return max(low, min(high, value))


def band_for_score(score: float, bands: dict | None = None) -> str:
    """Return LOW/MEDIUM/HIGH/CRITICAL for a numeric risk score."""
    if bands is None:
        from config.settings import RISK_BANDS  # local import avoids cycles

        bands = RISK_BANDS
    for label, (lo, hi) in bands.items():
        if lo <= score <= hi:
            return label
    return "LOW"


# -------- Random helpers ----------------------------------------------
def rnd_choice(seq: Iterable[Any]):
    """Tiny helper so the rest of the project reads more like natural English."""
    seq = list(seq)
    if not seq:
        raise ValueError("rnd_choice received an empty sequence")
    return random.choice(seq)


def weighted_rnd_choice(weights: dict) -> Any:
    """Pick a key from `weights` using the value as its probability."""
    population = list(weights.keys())
    probas = list(weights.values())
    total = sum(probas)
    if total <= 0:
        return rnd_choice(population)
    probas = [p / total for p in probas]
    return random.choices(population, weights=probas, k=1)[0]


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Division that returns `default` when denominator is zero."""
    if denominator == 0:
        return default
    return numerator / denominator


# -------- File helpers --------------------------------------------------
def ensure_dir(path: str | os.PathLike) -> None:
    """Create the directory (and parents) if it does not already exist."""
    os.makedirs(path, exist_ok=True)


# -------- Display helpers ----------------------------------------------
def truncate(text: str, length: int = 60) -> str:
    """Trim a string so long messages do not blow up table columns."""
    text = str(text)
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"


def split_csv(value: str) -> List[str]:
    """Split a comma-separated string into a cleaned list."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def join_csv(items: Iterable[str]) -> str:
    """Join an iterable into a CSV string."""
    return ", ".join(str(i) for i in items)


def severity_from_score(score: float) -> str:
    """Map a numeric score to a textual severity label."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def tuple_to_dict(columns: Tuple[str, ...], row: Tuple[Any, ...]) -> dict:
    """Pair a tuple of column names with a tuple of values (e.g. sqlite rows)."""
    return {col: row[i] if i < len(row) else None for i, col in enumerate(columns)}


def demo_participant_names() -> List[str]:
    """A short list of fictional names used for the gamification leaderboard."""
    return [
        "alice",
        "bob",
        "carol",
        "dave",
        "eve",
        "frank",
        "grace",
        "heidi",
        "ivan",
        "judy",
        "mallory",
        "oscar",
        "peggy",
        "trent",
        "victor",
    ]


def time_window_start(window_minutes: int) -> datetime:
    """Datetime that marks the beginning of the rolling risk window."""
    return now() - timedelta(minutes=window_minutes)