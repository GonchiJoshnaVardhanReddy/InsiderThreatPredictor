"""
Sentiment analysis — NLTK VADER wrapper.

Sentiment here is treated as an optional, contextual indicator. It is never
used to punish or label employees.
"""

from __future__ import annotations

from typing import Dict

from database import db_manager as db
from utils.helpers import log


class SentimentAnalyzer:
    """Light wrapper around NLTK's VADER SentimentIntensityAnalyzer."""

    def __init__(self) -> None:
        self._sia = None
        self._init_error: str | None = None
        self._load()

    # -----------------------------------------------------------
    def _load(self) -> None:
        try:
            import nltk
            from nltk.sentiment.vader import SentimentIntensityAnalyzer

            try:
                nltk.data.find("sentiment/vader_lexicon.zip")
            except LookupError:
                try:
                    nltk.download("vader_lexicon", quiet=True)
                except Exception as exc:  # pragma: no cover - network may be unavailable
                    log.warning("NLTK vader download failed: %s", exc)
                    self._init_error = str(exc)
                    return
            self._sia = SentimentIntensityAnalyzer()
        except Exception as exc:  # pragma: no cover - import-time failure
            self._init_error = str(exc)
            log.warning("Sentiment analyzer unavailable: %s", exc)

    @property
    def available(self) -> bool:
        return self._sia is not None

    @property
    def init_error(self) -> str | None:
        return self._init_error

    # -----------------------------------------------------------
    def analyse(self, text: str) -> Dict:
        """Return VADER scores + a friendly label."""
        text = (text or "").strip()
        if not text:
            return {
                "compound": 0.0, "pos": 0.0, "neu": 1.0, "neg": 0.0,
                "label": "NEUTRAL", "text": "",
            }
        if not self.available:
            # Fallback: extremely simple lexicon scoring.
            return self._fallback(text)

        scores = self._sia.polarity_scores(text)
        compound = float(scores.get("compound", 0.0))
        if compound >= 0.05:
            label = "POSITIVE"
        elif compound <= -0.05:
            label = "NEGATIVE"
        else:
            label = "NEUTRAL"
        result = {
            "compound": compound,
            "pos": float(scores.get("pos", 0.0)),
            "neu": float(scores.get("neu", 0.0)),
            "neg": float(scores.get("neg", 0.0)),
            "label": label,
            "text": text,
        }
        # Persist a row so the analyst can review the history later.
        try:
            db.insert_sentiment(text, result, label)
        except Exception as exc:
            log.warning("Could not persist sentiment row: %s", exc)
        return result

    def _fallback(self, text: str) -> Dict:
        positives = {"good", "great", "happy", "love", "excellent", "thanks", "appreciate"}
        negatives = {"bad", "angry", "hate", "terrible", "frustrated", "leak", "resign"}
        tokens = {t.strip(".,!?").lower() for t in text.split()}
        pos = sum(1 for t in tokens if t in positives) / max(len(tokens), 1)
        neg = sum(1 for t in tokens if t in negatives) / max(len(tokens), 1)
        neu = max(0.0, 1.0 - pos - neg)
        compound = pos - neg
        if compound >= 0.05:
            label = "POSITIVE"
        elif compound <= -0.05:
            label = "NEGATIVE"
        else:
            label = "NEUTRAL"
        return {
            "compound": round(compound, 3),
            "pos": round(pos, 3),
            "neu": round(neu, 3),
            "neg": round(neg, 3),
            "label": label,
            "text": text,
        }


# A shared instance so we don't reload the lexicon multiple times.
_analyzer: SentimentAnalyzer | None = None


def get_analyzer() -> SentimentAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = SentimentAnalyzer()
    return _analyzer