"""
Application-wide configuration constants.

Centralizing constants here makes the project easier to maintain.
"""

from pathlib import Path
import os

# -------- File-system paths ------------------------------------------------
# PROJECT_ROOT points to the directory that contains `main.py`.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = PROJECT_ROOT / "data"
MODELS_DIR: Path = PROJECT_ROOT / "models"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"
DB_PATH: Path = PROJECT_ROOT / "insider_threat.db"
SAMPLE_CSV: Path = DATA_DIR / "sample_data.csv"

# Make sure the required directories exist when the module is imported.
for _dir in (DATA_DIR, MODELS_DIR, REPORTS_DIR):
    _dir.mkdir(parents=True, exist_ok=True)


# -------- Application theme ---------------------------------------------
APP_TITLE: str = "INSIDER THREAT PREDICTOR"
APP_SUBTITLE: str = "AI-POWERED USER AND ENTITY BEHAVIOR ANALYTICS"
WINDOW_SIZE: str = "1450x900"
MIN_WINDOW_SIZE: str = "1200x750"

# Hex colours for the dark cybersecurity SOC look.
COLOUR_BG = "#0B132B"           # deep navy
COLOUR_PANEL = "#1C2541"        # charcoal panel
COLOUR_CARD = "#3A506B"         # lighter card
COLOUR_CYAN = "#5BC0BE"         # accent cyan
COLOUR_BLUE = "#0F4C81"         # accent blue
COLOUR_GREEN = "#2ECC71"        # normal / low risk
COLOUR_YELLOW = "#F1C40F"       # medium risk
COLOUR_RED = "#E74C3C"          # high / critical risk
COLOUR_TEXT = "#FFFFFF"
COLOUR_TEXT_DIM = "#A0AEC0"


# -------- Risk engine ---------------------------------------------------
# Default weights used by the rule-based scoring engine.
DEFAULT_RISK_WEIGHTS: dict = {
    "normal_activity": 0,
    "unusual_login_time": 5,
    "failed_login": 8,
    "large_download": 10,
    "usb_copy": 15,
    "restricted_file_access": 12,
    "bulk_data_transfer": 15,
    "privilege_escalation": 18,
}

# Below this inclusive threshold a user is treated as LOW risk.
DEFAULT_RISK_THRESHOLD: int = 20

# Rolling time window (minutes) used when computing risk score.
RISK_WINDOW_MINUTES: int = 60

# Hard cap so the score never exceeds 100.
RISK_SCORE_CAP: int = 100

# Risk band thresholds.
RISK_BANDS: dict = {
    "LOW": (0, 19),
    "MEDIUM": (20, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


# -------- Event simulation ---------------------------------------------
DEFAULT_SIM_INTERVAL_MS: int = 1500  # how often the simulator fires


# -------- ML -----------------------------------------------------------
MODEL_FILE: Path = MODELS_DIR / "isolation_forest.joblib"
FEATURE_COLUMNS = [
    "login_hour",
    "failed_login_count",
    "files_accessed",
    "download_volume_mb",
    "usb_activity",
    "privileged_access_count",
    "data_transfer_mb",
]


# -------- Kev behavioural model (primary detector) ----------------------
# Kev v3 is a LoRA-adapted Qwen3.5-0.8B trained on CERT r4.2 daily user-days.
# These values come from the published model card / deployment_metadata.json
# and are the contract the checkpoint was calibrated against — do not tune
# them here without re-calibrating the model.
KEV_MODEL_ID: str = os.environ.get("KEV_MODEL_ID", "joshnavardhan/kev-cert-r42-v3")

# Optional local checkpoint directory. When set and present it wins over the
# Hugging Face id, which is what makes an offline deployment possible.
KEV_LOCAL_PATH: str = os.environ.get("KEV_LOCAL_PATH", "")

# The Kev source checkout. `feature_builder.py` ships at its root and is NOT
# part of the installed `kev` package, so it has to be importable by path.
KEV_REPO_PATH: str = os.environ.get("KEV_REPO_PATH", "")

# Candidate locations probed when KEV_REPO_PATH is unset.
KEV_REPO_CANDIDATES = [
    r"C:\Users\gonch\OneDrive\Documents\Intership\kev",
    str(PROJECT_ROOT.parent / "kev"),
    str(PROJECT_ROOT / "kev"),
]

# Operating threshold published with the checkpoint. Chosen on the validation
# split only; on the CERT test split it yields ~0.70 recall at ~0.08 precision,
# i.e. most Kev alerts are false positives. It is set deliberately high.
KEV_THRESHOLD: float = 0.8279442191123962

# Seconds of quiet before a user is re-scored after new activity. Prevents the
# O(events x users) rescan that used to run on every single monitor event.
KEV_DEBOUNCE_SECONDS: float = 5.0



# -------- Departments and roles (fictional demo data) -------------------
DEPARTMENTS = [
    "Engineering",
    "Finance",
    "Human Resources",
    "Sales",
    "Research",
    "IT Security",
    "Operations",
]

ROLES = [
    "Software Engineer",
    "Senior Engineer",
    "Manager",
    "Analyst",
    "Administrator",
    "Intern",
    "Director",
]

ACCOUNT_STATUSES = ["ACTIVE", "MONITORED", "CONTAINED", "RESTRICTED"]