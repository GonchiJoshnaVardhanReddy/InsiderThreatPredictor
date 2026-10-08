"""
Incident response workflow.

All actions taken here operate *only* on the simulated application state.
No real account is disabled, no network is blocked and no file is deleted.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from database import db_manager as db
from engine.risk_engine import RiskEngine
from utils.helpers import iso_now, log


INCIDENT_STATUSES = ["OPEN", "UNDER INVESTIGATION", "CONTAINED", "RESOLVED"]

RESPONSE_ACTIONS = {
    "ACK":      ("Acknowledge", "Mark the incident as under investigation."),
    "INVEST":   ("Investigate", "Begin a simulated forensic investigation."),
    "CONTAIN":  ("Contain", "Move the user account to the simulated CONTAINED status."),
    "RESTORE":  ("Restore", "Lift the simulated containment and restore ACTIVE status."),
    "RESOLVE":  ("Resolve", "Close the incident as resolved."),
}


def list_incidents(status: Optional[str] = None) -> List[Dict]:
    return db.list_incidents(status=status)


def recommended_actions(incident: Dict) -> List[str]:
    """Suggest safe next steps based on the incident status."""
    status = incident.get("status", "OPEN")
    if status == "OPEN":
        return ["ACK", "INVEST"]
    if status == "UNDER INVESTIGATION":
        return ["CONTAIN", "RESOLVE"]
    if status == "CONTAINED":
        return ["RESTORE", "RESOLVE"]
    return []


def perform_action(incident_id: int, action: str, performed_by: str = "analyst") -> Dict:
    """Apply a simulated response action and log it."""
    if action not in RESPONSE_ACTIONS:
        raise ValueError(f"Unknown action: {action}")
    incident = db.get_incident(incident_id)
    if not incident:
        raise KeyError(f"Incident {incident_id} does not exist.")

    label, detail = RESPONSE_ACTIONS[action]
    user_id = int(incident["user_id"])

    if action == "ACK":
        db.update_incident_status(incident_id, "UNDER INVESTIGATION")
    elif action == "INVEST":
        db.update_incident_status(incident_id, "UNDER INVESTIGATION")
    elif action == "CONTAIN":
        db.update_incident_status(incident_id, "CONTAINED")
        db.set_user_status(user_id, "CONTAINED")
    elif action == "RESTORE":
        db.update_incident_status(incident_id, "RESOLVED")
        db.set_user_status(user_id, "ACTIVE")
    elif action == "RESOLVE":
        db.update_incident_status(incident_id, "RESOLVED")
    else:  # pragma: no cover
        raise ValueError(action)

    db.log_response_action(
        incident_id=incident_id,
        user_id=user_id,
        action_type=action,
        performed_by=performed_by,
        details=f"{label} — {detail}",
    )
    db.audit(
        performed_by,
        "incident_response",
        f"incident={incident_id} action={action} user={user_id}",
    )
    log.info("Incident %s action %s performed by %s", incident_id, action, performed_by)

    return {
        "ok": True,
        "incident_id": incident_id,
        "action": action,
        "performed_by": performed_by,
        "new_status": db.get_incident(incident_id)["status"],
        "timestamp": iso_now(),
    }


def recompute_risk_for_user(user_id: int, engine: RiskEngine) -> Dict:
    """Recompute the user risk and return the new assessment."""
    events = db.activity_for_user(user_id)
    assessment = engine.assess_user(user_id, events)
    db.update_user_risk(user_id, assessment.risk_score)
    db.insert_risk_history(user_id, assessment.risk_score, assessment.explanation)
    return {
        "user_id": user_id,
        "risk_score": assessment.risk_score,
        "band": assessment.band,
        "explanation": assessment.explanation,
    }


def incident_actions_for(incident_id: int) -> List[Dict]:
    """Return the action log for a single incident (newest first)."""
    return db.list_response_actions(incident_id=incident_id)


def actions_overview() -> List[Dict]:
    """Return the most recent response actions for any incident."""
    return db.list_response_actions()