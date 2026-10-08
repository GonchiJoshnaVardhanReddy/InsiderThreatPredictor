"""
High-level behavioural analysis API.

This is the single entry point the GUI uses. Pages never import the Kev
internals directly — they call the functions here and get plain dicts back.

Two detectors exist:

  * **Kev v3** (primary) — the baseline-aware behavioural model served by
    `kev_anomaly_detector`. It answers one question per user-day and is the
    detector behind everything the UI calls "AI".
  * **IsolationForest** (legacy, disabled by default) — the original
    unsupervised detector. scikit-learn is optional; the application starts
    and runs without it. Kept only as a fallback and clearly marked legacy.

Scoring is deliberately off the GUI thread and debounced: a monitor event
marks a user dirty, and a background thread scores them once the burst of
events settles. Scoring every user on every event was the old behaviour and
does not scale.
"""

from __future__ import annotations

import threading
from typing import Callable, Dict, List, Optional

from config.settings import KEV_DEBOUNCE_SECONDS
from utils.helpers import log

from . import kev_anomaly_detector as kev


# --------------------------------------------------------------------------- #
# Availability / status (cheap — safe to call from the GUI thread)
# --------------------------------------------------------------------------- #
def is_available() -> bool:
    """True unless Kev has definitively failed to initialise."""
    return kev.detector().status() != "error"


def is_trained() -> bool:
    """Kev ships pre-trained; 'trained' means the checkpoint is loaded."""
    return kev.detector().is_loaded()


def unavailable_reason() -> Optional[str]:
    return kev.detector().error()


def status() -> str:
    """not_loaded | loading | loaded | error"""
    return kev.detector().status()


def threshold() -> float:
    """The threshold currently in force (persisted override or the default)."""
    return kev.threshold()


def kev_cuda_available() -> bool:
    """True when the machine can run Kev on a GPU. Cheap; safe from the GUI."""
    return kev.detector().cuda_available()


def ensure_trained() -> Dict:
    """Start loading the checkpoint in the background and return its metadata.

    Non-blocking on purpose: loading pulls a ~1.7 GB base model and builds a
    CUDA context, which must not happen on the Tk main thread.
    """
    start_background_load()
    return model_info()


def ensure_loaded() -> bool:
    """Load synchronously. Only for tests and scripts — blocks for ~10s."""
    return kev.detector().load()


def start_background_load() -> None:
    d = kev.detector()
    if d.status() in ("loading", "loaded"):
        return
    threading.Thread(target=d.load, name="Kev-Loader", daemon=True).start()


def model_info() -> Dict:
    return kev.detector().model_info()


def summary() -> Dict:
    """Compact header/footer summary for the AI page and the dashboard."""
    d = kev.detector()
    info = d.model_info()
    results = d.cached_all()
    probabilities = [r.probability for r in results]
    info.update({
        "available": is_available(),
        "loaded": d.is_loaded(),
        "analyzed_users": len(results),
        "threat_count": sum(1 for r in results if r.is_threat),
        "normal_count": sum(1 for r in results if not r.is_threat),
        "highest_probability": max(probabilities) if probabilities else None,
        "average_probability": (sum(probabilities) / len(probabilities)) if probabilities else None,
        "threshold": kev.threshold(),
        "coverage": kev.adapter.coverage_summary(),
    })
    return info


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
def predict_for_user(user_id: int) -> Optional[Dict]:
    """Last cached result for one user, or None if they have not been scored."""
    result = kev.detector().cached(user_id)
    return result.as_dict() if result else None


def predict_for_all() -> List[Dict]:
    """Cached results for every scored user. Never blocks."""
    return [r.as_dict() for r in kev.detector().cached_all()]


def score_now(user_ids: Optional[List[int]] = None) -> List[Dict]:
    """Score synchronously in the calling thread. Used by scripts and tests."""
    d = kev.detector()
    if not d.is_loaded():
        return []
    results = d.score_all() if user_ids is None else [
        r for r in (d.score_user(uid) for uid in user_ids) if r is not None
    ]
    return [r.as_dict() for r in results]


# --------------------------------------------------------------------------- #
# Debounced background scoring
# --------------------------------------------------------------------------- #
_on_update: Optional[Callable[[List[Dict]], None]] = None
_pending: set = set()
_timer: Optional[threading.Timer] = None
_full_rescan = False
_lock = threading.Lock()
_worker_busy = False


def set_update_callback(callback: Optional[Callable[[List[Dict]], None]]) -> None:
    """Register a callback invoked with fresh results after each scoring run.

    The callback is called from the worker thread. The GUI is responsible for
    marshalling it onto the Tk event loop.
    """
    global _on_update
    _on_update = callback


def note_activity(user_id: int) -> None:
    """Mark one user as needing a Kev re-score, debounced."""
    global _timer
    with _lock:
        _pending.add(int(user_id))
        _arm_timer_locked()


def request_full_scan() -> None:
    """Queue a re-score of every user (used by the AI page's refresh button)."""
    global _timer, _full_rescan
    with _lock:
        _full_rescan = True
        _arm_timer_locked()


def _arm_timer_locked() -> None:
    """(Re)start the debounce timer. Caller must hold `_lock`."""
    global _timer
    if _timer is not None:
        _timer.cancel()
    _timer = threading.Timer(KEV_DEBOUNCE_SECONDS, _run_pending)
    _timer.daemon = True
    _timer.start()


def _run_pending() -> None:
    """Debounce expiry: score whatever is pending, off the GUI thread."""
    global _timer, _full_rescan, _worker_busy
    with _lock:
        _timer = None
        if _worker_busy:
            # A run is already in flight; re-arm so this batch is not lost.
            _arm_timer_locked()
            return
        users = sorted(_pending)
        _pending.clear()
        full = _full_rescan
        _full_rescan = False
        if not users and not full:
            return
        _worker_busy = True

    try:
        d = kev.detector()
        if not d.is_loaded():
            return
        if full:
            results = [r.as_dict() for r in d.score_all()]
        else:
            results = [
                r.as_dict()
                for r in (d.score_user(uid) for uid in users)
                if r is not None
            ]
        if results and _on_update is not None:
            _on_update(results)
    except Exception as exc:  # pragma: no cover - never kill the worker
        log.exception("Kev background scoring failed: %s", exc)
    finally:
        with _lock:
            _worker_busy = False
            if _pending or _full_rescan:
                _arm_timer_locked()


# --------------------------------------------------------------------------- #
# Legacy IsolationForest detector — optional, disabled by default
# --------------------------------------------------------------------------- #
def legacy_available() -> bool:
    """True when scikit-learn can be imported. Never imports it at module load."""
    try:
        from . import model_training
        return bool(model_training.SKLEARN_AVAILABLE)
    except Exception:
        return False


def legacy_status() -> Dict:
    if not legacy_available():
        return {"trained": False, "available": False}
    from . import model_training
    status = model_training.model_status()
    status["available"] = True
    return status


def legacy_train() -> Dict:
    """Train the legacy IsolationForest. Not part of the normal flow."""
    from . import model_training
    if not model_training.SKLEARN_AVAILABLE:
        raise RuntimeError(
            f"scikit-learn is not available: {model_training.SKLEARN_IMPORT_ERROR}"
        )
    return model_training.train_isolation_forest(force=True)


def legacy_predict_for_all() -> List[Dict]:
    if not legacy_available():
        return []
    from . import model_training
    return model_training.predict_anomalies()
