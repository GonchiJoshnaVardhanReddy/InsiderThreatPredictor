-- SQLite schema for the Insider Threat Predictor.
-- The application runs `init_db` on every startup; CREATE IF NOT EXISTS keeps
-- the call idempotent.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    department         TEXT NOT NULL,
    role               TEXT NOT NULL,
    email              TEXT NOT NULL UNIQUE,
    baseline_login_hour INTEGER NOT NULL DEFAULT 9,
    baseline_daily_downloads INTEGER NOT NULL DEFAULT 50,
    baseline_file_access    INTEGER NOT NULL DEFAULT 100,
    risk_score         REAL NOT NULL DEFAULT 0,
    account_status     TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_logs (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    event_type    TEXT NOT NULL,
    description   TEXT,
    risk_points   REAL NOT NULL DEFAULT 0,
    login_hour    INTEGER,
    files_accessed INTEGER,
    download_mb   REAL,
    usb_activity  INTEGER,
    privileged    INTEGER,
    data_transfer_mb REAL,
    timestamp     TEXT NOT NULL,
    -- Which collector produced this row (file_system, usb, eventlog, process,
    -- network, demo, demo_seed). Used by the Kev adapter to attribute activity
    -- to CERT-style features. NULL on rows written before this column existed.
    source        TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    risk_score  REAL NOT NULL,
    explanation TEXT,
    timestamp   TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    event_type  TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'OPEN',
    incident_id INTEGER,
    description TEXT,
    created_at  TEXT NOT NULL,
    acknowledged_at TEXT,
    resolved_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    trigger_score REAL NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN',
    summary       TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL,
    user_id      INTEGER NOT NULL,
    action_type  TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    details      TEXT,
    timestamp    TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)     REFERENCES users(user_id)     ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sentiment_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT NOT NULL,
    compound    REAL NOT NULL,
    positive    REAL NOT NULL,
    neutral     REAL NOT NULL,
    negative    REAL NOT NULL,
    label       TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenge_scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    participant TEXT NOT NULL,
    challenge   TEXT NOT NULL,
    score       INTEGER NOT NULL,
    correct     INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    details   TEXT,
    timestamp TEXT NOT NULL
);

-- Helpful indexes for faster lookups on the activity feed.
CREATE INDEX IF NOT EXISTS idx_activity_user_time
    ON activity_logs (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);