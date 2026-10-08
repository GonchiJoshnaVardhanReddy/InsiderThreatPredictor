"""
Kev v3 behavioural detector.

Owns the checkpoint: loading it once, running inference, and applying the
published operating threshold. Everything heavy (torch, transformers, the
checkpoint) is imported lazily so that importing this module — and therefore
starting the GUI — never requires a GPU, a 1.7 GB base model, or a network
connection.

Decision contract, taken from the checkpoint's deployment_metadata.json:
    question   "Does this employee activity indicate a potential insider threat?"
    options    ["false", "true"]           -> P(true) is the threat probability
    threshold  0.8279442191123962
    decision   probability >= threshold -> POTENTIAL_INSIDER_THREAT, else NORMAL

The model is never retrained here. Loading is the only expensive operation, it
happens once, and it is done off the GUI thread.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from config.settings import (
    KEV_LOCAL_PATH,
    KEV_MODEL_ID,
    KEV_THRESHOLD,
)
from utils.helpers import log

from . import kev_feature_adapter as adapter


QUESTION: Dict[str, Any] = {
    "instr": "Does this employee activity indicate a potential insider threat?",
    "options": ["false", "true"],
    "label": 0,
}

# The published operating point. An operator may override it from the Settings
# page; that override is persisted and audited, and this function is the single
# place the rest of the code reads the threshold from.
THRESHOLD_SETTING_KEY = "kev_threshold"


def threshold() -> float:
    """Current decision threshold: the persisted override, else the default."""
    try:
        from database import db_manager as db

        raw = db.get_setting(THRESHOLD_SETTING_KEY)
        if raw:
            value = float(raw)
            if 0.0 < value < 1.0:
                return value
    except Exception as exc:  # never let settings break scoring
        log.debug("Could not read the Kev threshold override: %s", exc)
    return KEV_THRESHOLD


@dataclass
class KevResult:
    """One scored user-day. Probabilities are 0.0-1.0 internally."""

    user_id: int
    user_name: str
    date: str
    probability: float
    threshold: float
    is_threat: bool
    label: str                       # POTENTIAL_INSIDER_THREAT | NORMAL
    baseline_anomaly_score: float
    baseline_history: int
    features: Dict[str, float] = field(default_factory=dict)
    deviations: Dict[str, float] = field(default_factory=dict)
    feature_coverage: Dict[str, str] = field(default_factory=dict)
    model: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "user_name": self.user_name,
            "date": self.date,
            "probability": self.probability,
            "threshold": self.threshold,
            "is_threat": self.is_threat,
            "label": self.label,
            "baseline_anomaly_score": self.baseline_anomaly_score,
            "baseline_history": self.baseline_history,
            "features": self.features,
            "deviations": self.deviations,
            "feature_coverage": self.feature_coverage,
            "model": self.model,
        }


class KevUnavailable(RuntimeError):
    """Raised when the detector cannot be used. Message is user-facing."""


class KevDetector:
    """Singleton-ish owner of the Kev checkpoint."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._load_lock = threading.Lock()
        self._tokenizer = None
        self._model = None
        self._device: Optional[str] = None
        self._status: str = "not_loaded"      # not_loaded | loading | loaded | error
        self._error: Optional[str] = None
        self._loaded_at: Optional[float] = None
        self._cache: Dict[int, KevResult] = {}

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #
    def status(self) -> str:
        return self._status

    def error(self) -> Optional[str]:
        return self._error

    def is_loaded(self) -> bool:
        return self._status == "loaded" and self._model is not None

    def device(self) -> Optional[str]:
        return self._device

    def torch_available(self) -> bool:
        try:
            import torch  # noqa: F401
            return True
        except Exception:
            return False

    def cuda_available(self) -> bool:
        try:
            import torch
            return bool(torch.cuda.is_available())
        except Exception:
            return False

    def gpu_name(self) -> Optional[str]:
        try:
            import torch
            if torch.cuda.is_available():
                return torch.cuda.get_device_name(0)
        except Exception:
            pass
        return None

    def model_reference(self) -> str:
        """The local path or hub id that will actually be loaded."""
        if KEV_LOCAL_PATH and Path(KEV_LOCAL_PATH).is_dir():
            return KEV_LOCAL_PATH
        return KEV_MODEL_ID

    def using_local_path(self) -> bool:
        return self.model_reference() != KEV_MODEL_ID

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    def _preflight(self) -> None:
        """Raise KevUnavailable with a specific reason if we cannot run."""
        try:
            import torch
        except Exception as exc:
            raise KevUnavailable(f"PyTorch is not installed: {exc}") from exc
        try:
            from kev.checkpoint import Checkpoint  # noqa: F401
        except Exception as exc:
            raise KevUnavailable(
                f"The 'kev' package is not importable: {exc}. Install it with "
                f"'pip install -e <kev-checkout>'."
            ) from exc
        reason = adapter.unavailable_reason()
        if reason:
            raise KevUnavailable(reason)
        if not torch.cuda.is_available() and self.device_preference() == "cuda":
            log.warning("CUDA requested but unavailable; Kev will run on CPU.")

    def device_preference(self) -> str:
        return os.environ.get("KEV_DEVICE", "cuda")

    def load(self, force: bool = False) -> bool:
        """Load the checkpoint. Safe to call repeatedly; loads at most once.

        Returns True when the model is ready. Never raises — failures are
        recorded in `status()`/`error()` so the UI can show a calm message
        instead of a traceback.
        """
        with self._load_lock:
            if self.is_loaded() and not force:
                return True

            try:
                self._preflight()
            except KevUnavailable as exc:
                self._status = "error"
                self._error = str(exc)
                log.warning("Kev unavailable: %s", exc)
                return False

            self._status = "loading"
            self._error = None
            try:
                import torch
                from kev.checkpoint import Checkpoint, LoadOptions

                reference = self.model_reference()
                device = self.device_preference() if torch.cuda.is_available() else "cpu"

                started = time.time()
                ckpt = Checkpoint(reference)
                options = LoadOptions(
                    dtype=torch.float32,
                    backend="torch",
                    merge=True,
                    cuda_graphs=False,
                    fused=False,
                )
                tokenizer, model = ckpt.load(device, options)
                model.eval()

                self._tokenizer = tokenizer
                self._model = model
                self._device = device
                self._loaded_at = time.time()
                self._status = "loaded"
                log.info(
                    "Kev '%s' loaded on %s in %.1fs",
                    reference, device, self._loaded_at - started,
                )

                # Warm up once. The first forward pass pays CUDA context and
                # kernel-selection costs (~15s observed); doing it here keeps
                # that cost off the first live scoring call.
                try:
                    self._warm_up()
                except Exception as exc:  # pragma: no cover - non-fatal
                    log.debug("Kev warm-up failed (ignored): %s", exc)

                return True
            except Exception as exc:
                self._status = "error"
                self._error = str(exc)
                self._tokenizer = None
                self._model = None
                log.exception("Kev model load failed: %s", exc)
                return False

    def _warm_up(self) -> None:
        frame = pd.DataFrame([{
            "user": "warmup", "day": pd.Timestamp.today().normalize(),
            "logon_count": 1, "unique_logon_pcs": 1, "after_hours_logons": 0,
            "device_events": 1, "unique_device_pcs": 1, "device_connects": 1,
            "device_disconnects": 0, "file_events": 1, "unique_files": 1,
            "unique_file_pcs": 1,
        }])
        builder = adapter.load_feature_builder()
        prepared = builder.prepare_daily_features(frame)
        self._score_frame(prepared)

    def ensure_loaded(self) -> bool:
        """Alias used by the app's startup sequence."""
        return self.load()

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #
    def _score_frame(self, prepared) -> List[KevResult]:
        """Run the model over an already-augmented user-day frame."""
        import torch

        builder = adapter.load_feature_builder()
        model = self._model
        tokenizer = self._tokenizer

        encodings = []
        for _, row in prepared.iterrows():
            state = builder.row_to_state(row)
            record = {"state": state, "questions": [QUESTION]}
            encodings.append(model.encode(tokenizer, record))

        results: List[KevResult] = []
        cutoff = threshold()
        with torch.no_grad():
            for index, per_record in enumerate(
                model.forward_batch(encodings, shared_prefix=True)
            ):
                logits = per_record[0]
                probability = float(torch.softmax(logits.float(), dim=-1)[1].item())
                row = prepared.iloc[index]
                is_threat = probability >= cutoff

                # Tolerate raw CERT-style frames that carry only `user`/`day`
                # and the ten base features, with no application ids.
                raw_id = row.get("user_id")
                user_id = int(raw_id) if raw_id is not None and not pd.isna(raw_id) else index
                user_name = str(
                    row.get("user_label") or row.get("user") or f"user_{user_id}"
                )

                results.append(
                    KevResult(
                        user_id=user_id,
                        user_name=user_name,
                        date=str(row["day"])[:10],
                        probability=probability,
                        threshold=cutoff,
                        is_threat=is_threat,
                        label="POTENTIAL_INSIDER_THREAT" if is_threat else "NORMAL",
                        baseline_anomaly_score=float(row["baseline_anomaly_score"]),
                        baseline_history=int(row["baseline_history"]),
                        features={
                            name: float(row[name])
                            for name in adapter.BASE_FEATURE_NAMES
                        },
                        deviations={
                            name: float(row.get(f"{name}_rel_dev", 0.0) or 0.0)
                            for name in adapter.BASE_FEATURE_NAMES
                        },
                        feature_coverage=adapter.coverage_for_result(row),
                        model=self.model_reference(),
                    )
                )
        return results

    def score_user(self, user_id: int) -> Optional[KevResult]:
        """Score one user's most recent day. None when there is no activity."""
        if not self.is_loaded():
            return None
        with self._lock:
            prepared = adapter.build_scoring_rows([int(user_id)])
            if prepared.empty:
                return None
            latest = prepared.sort_values("day").groupby("user").tail(1)
            results = self._score_frame(latest)
            if not results:
                return None
            result = results[0]
            self._cache[result.user_id] = result
            return result

    def score_all(self) -> List[KevResult]:
        """Score every user's most recent day."""
        if not self.is_loaded():
            return []
        with self._lock:
            prepared = adapter.build_scoring_rows()
            if prepared.empty:
                return []
            latest = prepared.sort_values("day").groupby("user").tail(1)
            results = self._score_frame(latest)
            self._cache = {r.user_id: r for r in results}
            return results

    def cached(self, user_id: int) -> Optional[KevResult]:
        with self._lock:
            return self._cache.get(int(user_id))

    def cached_all(self) -> List[KevResult]:
        with self._lock:
            return list(self._cache.values())

    # ------------------------------------------------------------------ #
    # Metadata
    # ------------------------------------------------------------------ #
    def model_info(self) -> Dict[str, Any]:
        return {
            "model": KEV_MODEL_ID,
            "reference": self.model_reference(),
            "local_path": self.model_reference() if self.using_local_path() else None,
            "threshold": threshold(),
            "status": self._status,
            "error": self._error,
            "device": self._device,
            "gpu": self.gpu_name(),
            "loaded_at": self._loaded_at,
            "repo_path": str(adapter.resolve_repo_path() or ""),
            "base_model": "Qwen/Qwen3.5-0.8B-Base",
            "dataset": "CERT r4.2",
            "model_version": "v3_baseline_aware",
        }


# Module-level singleton: the checkpoint is large, so there is exactly one.
_detector: Optional[KevDetector] = None
_detector_lock = threading.Lock()


def detector() -> KevDetector:
    global _detector
    with _detector_lock:
        if _detector is None:
            _detector = KevDetector()
        return _detector
