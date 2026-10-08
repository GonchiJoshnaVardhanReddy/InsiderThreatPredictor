"""
Cybersecurity challenges and gamification helpers.

Challenges are simple multiple-choice questions that help a beginner learn to
recognise suspicious behaviour. They never interact with real employees.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from database import db_manager as db
from utils.helpers import log


@dataclass
class Challenge:
    key: str
    title: str
    scenario: str
    question: str
    options: List[str]
    correct_index: int
    explanation: str
    points: int = 10


CHALLENGES: List[Challenge] = [
    Challenge(
        key="suspicious_login",
        title="Identify the suspicious login",
        scenario="An employee logs in at 03:12 from a country where they have never worked.",
        question="Which event type best classifies this activity?",
        options=["normal_activity", "unusual_login_time", "restricted_file_access", "failed_login"],
        correct_index=1,
        explanation="A login far from the user's baseline hour is flagged as unusual_login_time.",
    ),
    Challenge(
        key="abnormal_downloads",
        title="Spot the abnormal download",
        scenario="Marketing analyst pulls 1.4 GB of customer records in a single minute.",
        question="What is the most appropriate classification?",
        options=["large_download", "normal_activity", "failed_login", "privilege_escalation"],
        correct_index=0,
        explanation="Big single-shot downloads from a non-data team indicate large_download.",
    ),
    Challenge(
        key="usb_activity",
        title="Spot risky USB activity",
        scenario="An engineer copies proprietary source code to a personal USB stick.",
        question="Which event best fits?",
        options=["usb_copy", "unusual_login_time", "normal_activity", "bulk_data_transfer"],
        correct_index=0,
        explanation="USB copies are tracked as usb_copy and are high-risk.",
    ),
    Challenge(
        key="incident_classification",
        title="Classify the incident",
        scenario="A privileged account suddenly accesses HR folders it never touched before.",
        question="What should you do first?",
        options=[
            "Ignore it",
            "Mark as privilege_escalation and investigate",
            "Disable the user's keyboard",
            "Send a congratulations card",
        ],
        correct_index=1,
        explanation="Privilege escalation is the right label; an investigation should follow.",
    ),
    Challenge(
        key="unusual_behaviour",
        title="Detect unusual behaviour",
        scenario="An intern downloads 25 small files, runs a USB copy, and logs in at midnight.",
        question="What is the best summary?",
        options=[
            "Routine behaviour",
            "Multiple risk events combined",
            "Failed login attempt",
            "Normal browsing only",
        ],
        correct_index=1,
        explanation="Multiple suspicious events compound the risk score.",
    ),
]


def all_challenges() -> List[Challenge]:
    return CHALLENGES


def challenge_by_key(key: str) -> Challenge | None:
    for c in CHALLENGES:
        if c.key == key:
            return c
    return None


def evaluate_answer(challenge_key: str, selected_index: int) -> Dict:
    """Compare the selected answer with the correct one and persist a score row."""
    challenge = challenge_by_key(challenge_key)
    if challenge is None:
        raise KeyError(challenge_key)
    correct = int(selected_index) == challenge.correct_index
    points = challenge.points if correct else 0
    db.insert_challenge_score(
        participant="analyst",
        challenge=challenge.key,
        score=points,
        correct=1 if correct else 0,
        total=1,
    )
    db.audit(
        "analyst",
        "challenge_answer",
        f"{challenge.key} selected={selected_index} correct={correct}",
    )
    return {
        "challenge": challenge.key,
        "selected_index": int(selected_index),
        "correct": correct,
        "points_awarded": points,
        "correct_index": challenge.correct_index,
        "explanation": challenge.explanation,
    }


def leaderboard(limit: int = 10) -> List[Dict]:
    return db.leaderboard(limit=limit)


def reset_scores() -> None:
    """Delete all stored challenge scores (used by the Restart button)."""
    from database.db_manager import executemany

    executemany("DELETE FROM challenge_scores", [])
    log.info("Challenge leaderboard cleared.")