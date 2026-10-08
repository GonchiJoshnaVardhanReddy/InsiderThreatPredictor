"""
Risk engine — turns raw activity events into a 0-100 risk score.

The engine uses a *time-windowed* rule-based approach with decay:
* Each event type has a configurable weight.
* Only events that fall inside the rolling window (default: last 60 min) are counted.
* A small decay is applied to old events so risk does not stay elevated forever.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Tuple

from config.settings import (
    DEFAULT_RISK_THRESHOLD,
    DEFAULT_RISK_WEIGHTS,
    RISK_BANDS,
    RISK_SCORE_CAP,
    RISK_WINDOW_MINUTES,
)
from database import db_manager as db
from utils.helpers import band_for_score, clamp, iso_now, log, severity_from_score


# Each event type maps to a default weight. The weights can be overridden by
# the user via the Settings page and stored in the settings table.
EVENT_WEIGHTS: Dict[str, float] = {
    "normal_activity":         0,
    "unusual_login_time":      5,
    "failed_login":            8,
    "large_download":         10,
    "usb_copy":               15,
    "restricted_file_access": 12,
    "bulk_data_transfer":     15,
    "privilege_escalation":   18,
}

# How many "risk points" each event contributes per occurrence in the engine.
# (already in EVENT_WEIGHTS but kept here for documentation)


@dataclass
class RiskAssessment:
    """Result returned by `assess_user`."""
    user_id: int
    risk_score: float
    band: str
    explanation: str
    contributing_events: List[Tuple[str, float]]  # [(event_type, points), ...]


class RiskEngine:
    """Applies the rule engine on top of recent activity."""

    def __init__(self, weights: Dict[str, float] | None = None,
                 threshold: int | None = None,
                 window_minutes: int | None = None) -> None:
        self.weights: Dict[str, float] = dict(weights or DEFAULT_RISK_WEIGHTS)
        self.threshold: int = threshold if threshold is not None else DEFAULT_RISK_THRESHOLD
        self.window_minutes: int = window_minutes or RISK_WINDOW_MINUTES
        self._load_from_db()

    # --------------------------------------------------------------- #
    # Configuration
    # --------------------------------------------------------------- #
    def _load_from_db(self) -> None:
        """Pull the latest weights / threshold from the settings table."""
        weights_json = db.get_setting("risk_weights")
        if weights_json:
            try:
                stored = json.loads(weights_json)
                if isinstance(stored, dict):
                    self.weights.update({k: float(v) for k, v in stored.items()})
            except json.JSONDecodeError:
                log.warning("Stored risk_weights JSON is invalid; using defaults.")
        threshold_value = db.get_setting("risk_threshold")
        if threshold_value and threshold_value.isdigit():
            self.threshold = int(threshold_value)

    def update_weights(self, weights: Dict[str, float]) -> None:
        self.weights = dict(weights)
        db.set_setting("risk_weights", json.dumps(self.weights))

    def update_threshold(self, threshold: int) -> None:
        self.threshold = int(threshold)
        db.set_setting("risk_threshold", str(self.threshold))

    # --------------------------------------------------------------- #
    # Scoring
    # --------------------------------------------------------------- #
    def score_event(self, event_type: str) -> float:
        """Return the weight for a single event (0 if unknown)."""
        return float(self.weights.get(event_type, 0))

    def assess_user(self, user_id: int, events: Iterable[Dict]) -> RiskAssessment:
        """Compute the risk for one user using only events in the rolling window."""
        events_in_window: List[Dict] = []
        contributions: Dict[str, float] = defaultdict(float)
        occurrence_count: Dict[str, int] = defaultdict(int)
        now = datetime.now()

        for ev in events:
            ts = ev.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts_dt = datetime.fromisoformat(ts)
                except ValueError:
                    ts_dt = now
            elif isinstance(ts, datetime):
                ts_dt = ts
            else:
                ts_dt = now
            age_min = abs((now - ts_dt).total_seconds()) / 60.0
            if age_min > self.window_minutes:
                continue
            events_in_window.append(ev)

            ev_type = ev.get("event_type", "normal_activity")
            base = self.score_event(ev_type)
            # mild decay: the older the event, the less it counts.
            decay = max(0.4, 1.0 - (age_min / max(self.window_minutes, 1)))
            contribution = base * decay
            contributions[ev_type] += contribution
            occurrence_count[ev_type] += 1

        raw_score = sum(contributions.values())
        # Bonus for many events in the window.
        raw_score += 1.0 * sum(max(0, count - 3) for count in occurrence_count.values())
        capped = clamp(raw_score, 0.0, float(RISK_SCORE_CAP))
        capped_score = round(capped, 2)

        if contributions:
            explanation_parts = []
            for ev_type, pts in sorted(contributions.items(), key=lambda kv: -kv[1]):
                if pts <= 0:
                    continue
                explanation_parts.append(
                    f"{ev_type.replace('_', ' ')} ×{occurrence_count[ev_type]} (+{pts:.1f})"
                )
            explanation = "Score built from: " + ", ".join(explanation_parts)
        else:
            explanation = "No risky events in the rolling window."

        contributing = sorted(
            ((k, round(v, 2)) for k, v in contributions.items() if v > 0),
            key=lambda kv: -kv[1],
        )

        return RiskAssessment(
            user_id=user_id,
            risk_score=capped_score,
            band=band_for_score(capped_score, RISK_BANDS),
            explanation=explanation,
            contributing_events=contributing,
        )

    def assess_user_and_persist(self, user_id: int) -> RiskAssessment | None:
        """Recompute and persist one user's risk. Returns None for unknown users.

        This is the live path: a monitor event re-scores only the user it
        belongs to rather than rescanning everybody.
        """
        user = db.get_user(user_id)
        if not user:
            return None
        events = db.activity_for_user(user_id)
        assessment = self.assess_user(user_id, events)
        db.update_user_risk(user_id, assessment.risk_score)
        db.insert_risk_history(user_id, assessment.risk_score, assessment.explanation)
        if assessment.risk_score >= self.threshold:
            self._maybe_create_alert(user, assessment)
        return assessment

    def assess_all(self) -> Dict[int, RiskAssessment]:
        """Recompute risk for every user and persist the results."""
        assessments: Dict[int, RiskAssessment] = {}
        for user in db.list_users():
            assessment = self.assess_user_and_persist(user["user_id"])
            if assessment is not None:
                assessments[user["user_id"]] = assessment
        return assessments

    # --------------------------------------------------------------- #
    # Alerts
    # --------------------------------------------------------------- #
    def _reuse_or_open_incident(self, user: Dict, summary: str,
                                trigger_score: float) -> int:
        """Return an open incident for this user, opening one if needed.

        Reusing the open incident is what stops a repeat offender from
        generating a new incident on every scoring pass.
        """
        for inc in db.list_incidents(status="OPEN"):
            if inc["user_id"] == user["user_id"]:
                return int(inc["incident_id"])
        return db.insert_incident(user["user_id"], trigger_score, summary)

    def _maybe_create_alert(self, user: Dict, assessment: RiskAssessment) -> None:
        """Persist a rule-based alert (and an incident) when the threshold is crossed."""
        severity = severity_from_score(assessment.risk_score)
        summary_bits = ", ".join(
            f"{ev.replace('_', ' ')}({pts})"
            for ev, pts in assessment.contributing_events
        )
        description = f"Risk score {assessment.risk_score:.1f} (band {assessment.band}). {summary_bits}"

        incident_id = self._reuse_or_open_incident(
            user,
            f"Auto-opened by risk engine at {iso_now()}.",
            assessment.risk_score,
        )

        alert_id = db.insert_alert(
            user_id=user["user_id"],
            event_type="threshold_breach",
            risk_score=assessment.risk_score,
            severity=severity,
            description=description,
            incident_id=incident_id,
        )
        db.link_alert_to_incident(alert_id, incident_id)
        db.audit(
            "risk_engine",
            "alert_created",
            f"user={user['user_id']} score={assessment.risk_score:.1f}",
        )

    def raise_kev_alert(self, result: Dict) -> int | None:
        """Raise an alert for a Kev threat result, reusing the user's open incident.

        Deduplicated on the open alert for this user, so a user whose day stays
        above the threshold does not accumulate one alert per scoring pass.
        Returns the alert id, or None when one was already open.

        No containment is performed here — response actions remain simulated
        and audited elsewhere in the application.
        """
        user_id = int(result["user_id"])
        if db.has_open_alert(user_id, "kev_insider_threat"):
            return None

        user = db.get_user(user_id) or {"user_id": user_id, "name": result.get("user_name")}
        probability = float(result["probability"])
        threshold = float(result["threshold"])
        coverage = result.get("feature_coverage") or {}
        weak = sorted(k for k, v in coverage.items() if v in ("proxy", "degenerate", "absent"))
        features = result.get("features") or {}
        feature_bits = ", ".join(f"{k}={v:.0f}" for k, v in sorted(features.items()))

        description = (
            f"Kev behavioural model: probability {probability:.4f} "
            f"(threshold {threshold:.4f}) on {result.get('date', '-')}. "
            f"Baseline anomaly {float(result.get('baseline_anomaly_score') or 0):.4f} "
            f"over {int(result.get('baseline_history') or 0)} prior observations. "
            f"Model {result.get('model', '-')}. "
            f"Features: {feature_bits}. "
            f"Adapted from Windows telemetry; weak mappings: "
            f"{', '.join(weak) if weak else 'none'}. "
            f"Behavioural risk signal — not proof of malicious activity."
        )

        incident_id = self._reuse_or_open_incident(
            user,
            f"Kev behavioural model flagged {result.get('date', '-')} "
            f"(p={probability:.4f}); opened at {iso_now()}.",
            probability * 100.0,
        )

        # Kev is a probability, not the 0-100 rule score, so it is mapped to a
        # severity band rather than pretending to be the same scale.
        alert_id = db.insert_alert(
            user_id=user_id,
            event_type="kev_insider_threat",
            risk_score=probability * 100.0,
            severity=severity_from_score(probability * 100.0),
            description=description,
            incident_id=incident_id,
        )
        db.link_alert_to_incident(alert_id, incident_id)
        db.audit(
            "kev_detector",
            "kev_alert_created",
            f"user={user_id} probability={probability:.4f} "
            f"threshold={threshold:.4f} date={result.get('date', '-')}",
        )
        log.info("Kev alert raised for user %s (p=%.4f)", user_id, probability)
        return alert_id


def load_engine() -> RiskEngine:
    """Build a RiskEngine instance using whatever the user has saved in settings."""
    return RiskEngine()