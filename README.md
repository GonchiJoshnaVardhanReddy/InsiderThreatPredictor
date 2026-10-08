# Insider Threat Predictor

> A Windows SOC desktop application for **User and Entity Behaviour Analytics
> (UEBA)** — it observes real activity on the machine it runs on, scores it
> with a rule-based risk engine, and runs the **Kev v3 behavioural model** as
> its primary AI detector.

Built as a cybersecurity internship project. Python 3.12 / 3.13, CustomTkinter,
SQLite, PyTorch.

---

## What this application is

The application runs **on the endpoint you want to monitor** and behaves like a
small security operations console:

```
Windows activity  →  activity_logs  →  rule risk engine + Kev v3 model
                                  →  risk + anomaly results
                                  →  Dashboard / Alerts / Incidents / Reports
```

There is **no synthetic data by default**. Every row in the activity table is a
real observation from a real monitor. The synthetic generator exists only so the
system can be demonstrated on a quiet machine, and everything it produces is
labelled as simulated.

### What the AI output means — read this first

> **Kev is a behavioural risk signal, not proof of malicious activity.**
>
> Kev v3 was trained on **CERT-style daily user activity**, not on Windows
> telemetry. This application maps the Windows events it collects onto that
> feature set — a documented, application-specific adaptation
> (see [Domain adaptation](#domain-adaptation-the-windows-to-cert-mapping)).
> It is **not** a claim that a CERT-trained model has been retrained for
> Windows, and its output is **not** a finding that an employee has done
> something wrong.
>
> A high Kev probability means **"this employee-day is worth an analyst's
> attention"**. It always requires human review. Every response action the
> application offers is simulated and written to an audit log — no real account
> is disabled, no network is blocked, no file is deleted.
>
> Kev's published operating threshold is deliberately high, and its own
> validation reports roughly 0.70 recall at roughly 0.08 precision on the CERT
> test split. **Most Kev alerts are expected to be false positives.** That is
> the intended trade-off, not a defect: it is a triage signal, not a verdict.

---

## Table of contents

1. [Architecture](#architecture)
2. [End-to-end dataflow](#end-to-end-dataflow)
3. [The three analysis layers](#the-three-analysis-layers)
4. [The Kev behavioural model](#the-kev-behavioural-model)
5. [Domain adaptation: the Windows-to-CERT mapping](#domain-adaptation-the-windows-to-cert-mapping)
6. [Alerting and incident workflow](#alerting-and-incident-workflow)
7. [Database schema](#database-schema)
8. [The GUI, page by page](#the-gui-page-by-page)
9. [Activity simulation and the live demonstration runbook](#activity-simulation-and-the-live-demonstration-runbook)
10. [Installation](#installation)
11. [Running it](#running-it)
12. [Verification and tests](#verification-and-tests)
13. [Performance and threading model](#performance-and-threading-model)
14. [Safety and ethical notes](#safety-and-ethical-notes)
15. [Troubleshooting](#troubleshooting)
16. [Known limitations](#known-limitations)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — COLLECTION                              (background threads)   │
│                                                                          │
│   file_monitor      watchdog           file writes in watched folders    │
│   process_monitor   psutil             process start/stop, high CPU      │
│   network_monitor   psutil             per-NIC byte deltas               │
│   usb_monitor       psutil             removable-media arrival           │
│   eventlog_monitor  pywin32            Security log 4624/4625/4672/4720  │
│                                        (falls back to the Application log)│
│                              │                                           │
│                              ▼                                           │
│                    activity_logs  (SQLite, one row per observation)      │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────────┐
│ LAYER 2 — ANALYSIS                                                       │
│                                                                          │
│   engine/risk_engine.py        rules: weights × recency decay → 0..100   │
│                                (runs on EVERY event, always)             │
│                                                                          │
│   ai/kev_feature_adapter.py    activity_logs → one row per user per day  │
│   ai/kev_anomaly_detector.py   Kev checkpoint: load, infer, threshold    │
│   ai/anomaly_detector.py       facade + 5 s debounce + worker thread     │
│                                                                          │
│   ai/model_training.py         legacy IsolationForest (optional, off)    │
│   ai/sentiment_analyzer.py     NLTK VADER, contextual only               │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────────┐
│ LAYER 3 — DECISION AND PRESENTATION                (Tk main thread only) │
│                                                                          │
│   alerts        rule breach or Kev breach → alert row                    │
│   incidents     one OPEN incident per user, reused, never duplicated     │
│   response      Acknowledge → Investigate → Contain → Restore → Resolve  │
│                 (simulated, audited)                                     │
│   GUI           Dashboard · Live Monitoring · AI Risk Prediction ·      │
│                 Alerts · Response · Sentiment · Challenges · Reports ·   │
│                 Settings · User Management                               │
└──────────────────────────────────────────────────────────────────────────┘
```

The two data sources — real monitors and the activity simulator — write into the
**same** `activity_logs` table, so nothing downstream needs to know which
produced a row. Each row records its `source` so the Kev adapter can attribute
activity correctly.

---

## End-to-end dataflow

This is the full path an event takes, from the operating system to a number on
the dashboard.

### Step 1 — Collection

A monitor observes something on the machine and builds a `MonitorEvent`
(`monitor/base.py`):

| Field | Meaning |
|---|---|
| `source` | which monitor produced it (`file_system`, `process_monitor`, …) |
| `event_type` | the app's vocabulary, e.g. `usb_copy`, `unusual_login_time` |
| `description` | human-readable detail |
| `risk_points` | the event's weight under the current rule configuration |
| `user_id` | which employee the event is attributed to |
| `payload` | monitor-specific extras |
| `timestamp` | ISO-8601 |

Monitors run on **daemon threads**. They never touch Tk.

### Step 2 — Persistence

The manager hands the event to the risk engine and to `activity_logs`:

* `activity_logs` keeps the raw observation (with `source`).
* `risk_history` keeps the scored risk for the user at that moment.

### Step 3 — Rule scoring (always)

`engine/risk_engine.py` recomputes the user's score from the rolling window:

```
score = Σ over events in window of  risk_points × max(0.4, 1 − age_min / 60)
score = min(score, 100)
```

Bands: LOW 0–19, MEDIUM 20–49, HIGH 50–74, CRITICAL 75–100. The explanation
string records exactly which events contributed how many points, so a score is
always auditable.

This runs on **every** event for the affected user only. It is cheap and it
never waits for the model.

### Step 4 — Kev scoring (debounced, background)

The same event also calls `anomaly_detector.note_activity(user_id)`, which:

1. adds the user to a pending set,
2. arms a **5-second debounce timer**,
3. when the timer expires, scores **only the pending users** on a worker thread,
4. marshals the results back to the Tk event loop via `app.after(0, …)`.

A burst of 300 file events therefore causes **one** model pass, not 300. A
monitor event never triggers a full re-scan of every user.

### Step 5 — Feature adaptation (inside the model pass)

For each user being scored:

1. `activity_logs` rows are aggregated into **one row per user per day**.
2. The ten CERT-style base features are computed from those rows.
3. `day_of_week` and `is_weekend` are derived from the date.
4. The table is passed through the Kev checkout's own
   `feature_builder.prepare_daily_features()`, which adds `baseline_history`,
   `baseline_anomaly_score` and the ten `*_rel_dev` deviation features.

### Step 6 — Inference and threshold

The prepared rows go through the checkpoint (`model.encode` →
`model.forward_batch`) and come back as `[P(false), P(true)]`. The probability
of `true` is the insider-threat probability.

```
probability >= 0.8279442191123962  →  POTENTIAL_INSIDER_THREAT
probability <  0.8279442191123962  →  NORMAL
```

The threshold is read at scoring time, so a Settings change takes effect on the
next pass.

### Step 7 — Decision and escalation

A `KevResult` is cached per user and pushed to the GUI. If
`is_threat` is true, the application escalates:

* an **alert** is raised carrying the probability, the threshold used, the model
  name, the date and a feature summary;
* an **incident** is created — or an existing **open** incident for that user is
  reused, so duplicates are impossible;
* an **audit entry** is written.

### Step 8 — Presentation

The Dashboard renders the rule KPIs and the Kev KPIs **side by side**, on
separate scales, never merged into one unexplained number. The AI Risk
Prediction page shows the per-user table and a detail view.

---

## The three analysis layers

| Layer | What it is | Runs when | Status |
|---|---|---|---|
| **Rule risk engine** | Weighted event rules with a 60-minute recency decay, clamped to 100 | On every event | **Primary rule detector.** Unchanged by the Kev integration. |
| **Kev v3** | LoRA-adapted `Qwen/Qwen3.5-0.8B-Base` with a pointer head, baseline-aware daily features | Debounced, ~5 s after activity settles; only the affected users | **Primary AI detector** |
| **IsolationForest** | scikit-learn unsupervised outlier detector on 7 aggregate features | Only if explicitly invoked | **Legacy.** Optional, off by default. scikit-learn is not imported at startup. |

**The rule score and the Kev probability are deliberately never combined.** They
measure different things — one is a deterministic points total over a 60-minute
window, the other is a model probability over a whole day of behaviour — and
merging them would produce a number nobody could explain. They are shown
separately, labelled separately.

---

## The Kev behavioural model

### Identity

| | |
|---|---|
| Model | `joshnavardhan/kev-cert-r42-v3` (Hugging Face) |
| Family | Kev-0.8B |
| Base | `Qwen/Qwen3.5-0.8B-Base` |
| Trained on | CERT r4.2 daily user-day features |
| Checkpoint version | `v3_baseline_aware` |

### The decision contract

Kev answers exactly one question, per employee-day:

> **Does this employee activity indicate a potential insider threat?**

with the options `["false", "true"]`. The probability of option index 1 is the
insider-threat probability. Decisions use the published operating point:

```
probability >= 0.8279442191123962  →  POTENTIAL_INSIDER_THREAT
probability <  0.8279442191123962  →  NORMAL
```

The comparison is **inclusive** at the boundary. Probabilities are kept as
0.0–1.0 internally; the UI may show them as 0–100 %.

### Baseline-aware features

Beyond the ten base features, the model consumes per-user baselines. The
contract is exact and is implemented by the Kev checkout's own
`feature_builder.prepare_daily_features()` — this repository reuses it rather
than reimplementing the algorithm:

* baselines are **per user**;
* only **prior** observations count — a day never sees its own value;
* rolling window of **30** days;
* a **minimum of 10** observations before a baseline exists;
* the baseline is the **median**;
* deviation is `abs(current − baseline) / (baseline + 1)`;
* days without enough history get a deviation of **0.0**, never an invented
  number;
* `baseline_history` is capped at 30.

The result object carries `baseline_history` (how many days of history backed
the baseline) and `baseline_anomaly_score`, so the UI can show *why* a
probability is what it is — a user with 3 days of history is not saying the same
thing as a user with 30.

### Result object

Each scored user-day produces a typed record with:

`user_id`, `user_name`, `date`, `probability`, `threshold`, `is_threat`,
`label`, `baseline_anomaly_score`, `baseline_history`, `features`,
`deviations`, `feature_coverage`, `model`.

`features` holds the ten base values; `deviations` holds their relative
deviations from the user's own baseline; `feature_coverage` maps each feature to
its Windows→CERT mapping verdict.

### Loading and lifecycle

* The checkpoint is loaded **once**, on a background thread started at launch.
* Loading is **~10–18 s** (the base model is ~1.7 GB) and is never done on the
  Tk main thread.
* The GUI shows **"Kev loading…"** until it finishes; the rest of the
  application is fully usable meanwhile.
* A warm-up inference pass is paid during load, so the first live score is not
  the cold start.
* **The model is never retrained by this application.** There is no retrain
  entry point; `tests/test_anomaly_detector.py` asserts that one cannot be
  reintroduced without failing the suite.
* If the checkpoint cannot be loaded, the AI page reports the reason and the
  rest of the application keeps working.

---

## Domain adaptation: the Windows-to-CERT mapping

Kev was trained on CERT-style **daily user behaviour**. This application
collects **Windows telemetry**. Those are not the same thing, and the adapter
does not pretend they are.

`ai/kev_feature_adapter.py` is the single module that crosses that boundary. It
is explicitly a **prototype domain adaptation layer**: it aggregates
`activity_logs` into one row per user per day, produces the ten base features
where the collected data supports them, derives `day_of_week` and `is_weekend`,
and then hands the table to the Kev feature builder.

Every feature carries a **coverage verdict**, visible in the AI page's
**Coverage Report** and attached to every result:

| Verdict | Meaning |
|---|---|
| `direct` | Windows telemetry carries this quantity as-is |
| `proxy` | a defensible stand-in, but not the same measurement |
| `degenerate` | cannot vary on a single-machine deployment |
| `absent` | no Windows counterpart; the feature stays 0 |

### The mapping, feature by feature

| CERT feature | Verdict | Source in this app | Honest caveat |
|---|---|---|---|
| `logon_count` | `proxy` | eventlog rows typed `unusual_login_time` | Windows emits no logon census to this app; only logons surfaced by the event log are counted, so it **systematically undercounts** versus CERT |
| `unique_logon_pcs` | `degenerate` | 1 when any logon was seen that day, else 0 | one host; source workstation per logon is not recorded. CERT saw many PCs per user |
| `after_hours_logons` | `proxy` | logon rows outside 08:00–18:00 | a fixed working window, not the organisation's real calendar; inherits the undercount above |
| `device_events` | `direct` | rows typed `usb_copy` or `source=usb` | the USB monitor reports removable-media arrivals directly |
| `unique_device_pcs` | `degenerate` | 1 when any device event was seen, else 0 | single host; cannot exceed 1 as it did in CERT |
| `device_connects` | `proxy` | same rows as `device_events` | the monitor reports arrival, not a connect/disconnect pair |
| `device_disconnects` | `absent` | always 0 | no Windows counterpart is collected |
| `file_events` | `proxy` | rows in the file event set, or `source=file_system` | a **sample** of file activity, not CERT's full audit trail |
| `unique_files` | `proxy` | distinct descriptions among file rows that day | descriptions embed the file name, so this approximates distinct-file counts without persisting paths |
| `unique_file_pcs` | `degenerate` | 1 when any file event was seen, else 0 | single host; cannot exceed 1 as it did in CERT |

**What this means in practice.** Three of the ten features are `degenerate` on a
single-machine deployment and one is `absent`, so those carry no signal here. The
model still runs on all of them — the feature contract is fixed and the
checkpoint was trained against it — but the honest reading is that
**the effective signal comes from the logon, device and file volume features and
their deviations from each user's own baseline.**

The adapter never invents precision to fill a gap. Where a CERT feature cannot
be faithfully reconstructed, it uses the closest defensible value and records
the verdict. If a `degenerate` or `absent` feature ever comes back non-zero, the
adapter logs a warning rather than silently trusting it.

---

## Alerting and incident workflow

```
                    ┌────────────────────────┐
   rule score ≥ threshold ──┐                 │
                    │       ├──►  ALERT  ────┼──► open INCIDENT for that user
   Kev is_threat ───┘       │   (probability, │        (reused if one is
                            │    threshold,   │         already open)
                            │    model, date, │
                            │    feature      │
                            │    summary)     │
                            └────────────────────────┘
                                       │
                                       ▼
                     Acknowledge → Investigate → Contain → Restore → Resolve
                              (simulated · every step audit-logged)
```

* Either detector can raise an alert on its own; they are independent paths.
* A Kev alert records **which** signal produced it and the numbers behind it, so
  an analyst can judge it.
* **Duplicate open incidents are not created.** Before opening one, the
  application looks for an existing open incident for that user and links to it.
  This is verified by `verify_build.py` check 12.
* **Nothing is actually contained.** Containment is a database row and an audit
  entry. No account is disabled, no process is killed, no network is blocked.

---

## Database schema

SQLite, created and migrated automatically at launch. Ten tables:

| Table | Holds |
|---|---|
| `users` | the (fictional) employees being monitored |
| `activity_logs` | every raw observation, with its `source` |
| `risk_history` | the rule score for a user at a point in time |
| `alerts` | raised alerts, their severity, status and detail |
| `incidents` | incidents, with status and the linked alert |
| `response_actions` | each simulated response step, with who and when |
| `sentiment_history` | VADER sentiment scores |
| `challenge_scores` | gamified-training results and leaderboard |
| `settings` | persisted configuration (risk weights, threshold, interval) |
| `audit_log` | actor, action, detail, timestamp for every state change |

Migrations are additive and idempotent — for example, the `source` column on
`activity_logs` is added once if missing and never rewrites existing rows.

---

## The GUI, page by page

| Page | What it does |
|---|---|
| **Dashboard** | Monitor status; rule KPIs; Kev KPIs (`AI Threats`, `Highest Kev Risk`, `Average Kev Risk`); risk distribution, per-user bars and a trend chart; the latest alerts; the activity-simulator controls. |
| **User Management** | Create, edit and delete the fictional employees. |
| **Live Monitoring** | The live feed: real monitor events and simulated activity, tagged by source, colour-coded by risk band. |
| **AI Risk Prediction** | Kev status, model name, threshold, analyzed users, and the per-user table — **User / Kev Probability / Decision / Baseline Anomaly / History / Last Updated**. Select a row for the detail view: every feature value, its deviation from that user's own baseline, its mapping verdict and the model name. **Coverage Report** opens the full mapping table. |
| **Sentiment Analysis** | NLTK VADER scoring of free text. Contextual only; never an accusation. |
| **Security Alerts** | Filter, acknowledge and resolve alerts; link an alert to an incident. |
| **Automated Response** | The incident workflow. Acknowledge → Investigate → Contain → Restore → Resolve. |
| **Cyber Challenges** | Gamified security questions and a leaderboard. |
| **Reports** | CSV and PDF export: user risk report, alerts summary, activity history, incident history, and a PDF security brief. |
| **Settings** | Monitor toggles; risk weights; the Kev model card (model, source, device, status, feature builder); the decision threshold; the activity-simulator interval; reset. |

### Reading the two risk numbers

* **Rule risk** is 0–100 and means "how many weighted points has this user
  accumulated in the last 60 minutes".
* **Kev probability** is 0–100 % and means "how much does this employee's whole
  day look like the insider-threat pattern the model was trained on".

They answer different questions and can legitimately disagree. The Dashboard
labels the Kev tiles **"Kev probability, not the rule score"** so the two are
never confused.

---

## Activity simulation and the live demonstration runbook

The application works on real data with no setup. The simulator exists only for
demonstrating it on a machine that is not generating interesting activity.

**It is not evidence that the model is accurate.** It demonstrates that the
pipeline runs end to end: activity rows change, the rule score changes, the Kev
features change, and the Kev prediction updates.

### Starting it

Use the **▶ Simulate Activity** button — it appears on both the **Dashboard** and
**Live Monitoring**, and the two stay in sync (start on one page, and the other
shows the truth when you get there). The opposite button disables itself, so the
controls always reflect reality.

The first start also backfills labelled synthetic history, because the
baseline-aware model needs prior days to have a baseline to compare against.

### What to expect

1. The feed on **Live Monitoring** fills with rows tagged `simulated`.
2. Rule risk scores move within the 60-minute window.
3. Every ~25 ticks one user enters a short amplified-activity episode — that is
   what makes the behavioural features move rather than just the row count.
4. Within ~5 seconds of each burst, the Kev pass runs and the AI Risk Prediction
   page updates.
5. If a user crosses the threshold, an alert and an incident appear.

**Crossing the threshold is uncommon, and that is expected.** The published
threshold is deliberately high, and the synthetic history is a baseline of
ordinary days — so a single burst moves a user's probability by a visible
amount without usually reaching the operating point. What the simulator
demonstrates is that the pipeline runs and responds: activity rows change, the
rule score changes, the baseline deviations change, and the probability changes
with them. It is not a demonstration of detection accuracy.

### Stopping it

Press **■ Stop Activity** on either page. The generator stops immediately, the
buttons swap state, and the feed returns to real monitor events only.

### Resetting

**Settings → Reset all data** wipes activity, alerts, incidents and challenge
scores, keeping users and settings. The Kev checkpoint is unaffected — it is
loaded from disk, not stored in the database.

To start completely fresh, close the app, delete `insider_threat.db`, and
relaunch; it is recreated and seeded automatically.

---

## Installation

The shortest version is in [BUILD.md](BUILD.md). In full:

```powershell
cd "C:\path\to\InsiderThreatPredictor"

# 1. A Python 3.12 or 3.13 environment (Kev requires >=3.12,<3.14)
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. The application's dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. The Kev package and its feature builder
pip install -e "C:\path\to\kev-checkout"
$env:KEV_REPO_PATH = "C:\path\to\kev-checkout"
```

`feature_builder.py` ships at the **root** of the Kev checkout, outside the
installed package, so it has to be importable by path — that is what
`KEV_REPO_PATH` is for. The Settings page shows which path was found.

`scikit-learn` and `joblib` are listed for the legacy detector only; the
application starts and runs without them.

### Model configuration

| Setting | Default | Meaning |
|---|---|---|
| `KEV_MODEL_ID` | `joshnavardhan/kev-cert-r42-v3` | checkpoint on the Hugging Face hub |
| `KEV_LOCAL_PATH` | *(empty)* | a local checkpoint directory; **wins over** the hub id when it exists |
| `KEV_REPO_PATH` | *(auto-probed)* | the Kev checkout holding `feature_builder.py` |
| `KEV_DEVICE` | `cuda` | falls back to `cpu` automatically |

### Offline deployment

True offline operation requires the checkpoint **and** its base model to be
already on disk.

```powershell
# once, while online
huggingface-cli download joshnavardhan/kev-cert-r42-v3 --local-dir D:\models\kev-cert-r42-v3
huggingface-cli download Qwen/Qwen3.5-0.8B-Base          --local-dir D:\models\qwen3.5-0.8b-base

# then, offline
$env:KEV_LOCAL_PATH = "D:\models\kev-cert-r42-v3"
$env:HF_HUB_OFFLINE = "1"
```

Without a local copy and without a network, the AI page reports
`Kev unavailable` and everything else keeps working. The application is not
designed around network access.

---

## Running it

```powershell
.\run.ps1
```

`run.ps1` resolves a supported interpreter, refuses to launch on an unsupported
Python version, runs the build verification against a throwaway database, and
then starts `main.py`.

```powershell
.\run.ps1 -SkipVerify                  # launch without verifying
.\run.ps1 -SkipModel                   # verify, but skip the two model checks
.\run.ps1 -Python C:\path\to\python.exe
```

If your interpreter is not in `.venv` or on `PATH`, record it once:

```powershell
Set-Content .python-path "C:\path\to\python.exe"
```

Or launch by hand:

```powershell
python scripts\verify_build.py     # optional
python main.py
```

### Startup order

1. Initialise the database (create, migrate, seed).
2. Start loading the Kev checkpoint **on a background thread**.
3. Build the GUI.
4. Start the OS monitors.
5. Start the Kev scoring worker.
6. Show the Dashboard.

No long-running Transformer inference ever happens on the Tk main thread.

---

## Verification and tests

```powershell
python -m compileall -q ai gui engine monitor database config scripts main.py
python scripts\verify_build.py          # 12 environment + pipeline checks
python scripts\smoke_test_kev.py        # load the model, score two user-days
python -m unittest discover -s tests    # unit tests
```

* `verify_build.py` runs against a **throwaway database** and needs no CERT
  files. It reports `SKIP` rather than `FAIL` for the two GPU-dependent checks
  on a CPU-only machine, so it is useful either way.
* `smoke_test_kev.py` builds a tiny synthetic history for two users and prints
  the probability and decision for each, so the pipeline can be exercised
  without touching the application database.

### The twelve build checks

| # | Check |
|---|---|
| 1 | Supported interpreter (3.12 / 3.13) |
| 2 | Required imports resolve |
| 3 | Database creates and migrates |
| 4 | Schema contains every expected table |
| 5 | Configuration loads (threshold, debounce, paths) |
| 6 | `feature_builder` produces the v3 baseline features |
| 7 | The Windows telemetry adapter aggregates into user-day rows |
| 8 | The Kev checkpoint loads |
| 9 | Kev inference runs on a synthetic user-day |
| 10 | The result object exposes the documented fields |
| 11 | The threshold decision follows the published rule, boundary inclusive |
| 12 | A threat result creates an alert, an incident and an audit entry, deduplicated |

`tests/test_pdf_report.py` covers the PDF briefing separately: it builds a
brief against a throwaway database, checks the `%PDF-` signature and `%%EOF`
terminator, extracts the drawn text and compares it with the database state,
and asserts that a failing export is reported to the analyst rather than
raised into the Tk callback.

---

## Performance and threading model

Measured on an RTX 5060 Laptop GPU:

| Operation | Time |
|---|---|
| Checkpoint load (first, cached base model) | ~10–18 s |
| Warm-up pass | ~1 s |
| Steady-state prediction | ~0.20 s per row |
| Peak VRAM | ~3.1 GB |

Design rules:

* the checkpoint is loaded **once** and cached;
* a monitor event does **not** trigger a full re-scan — only the affected user is
  marked dirty and scored after a **5-second debounce**;
* all inference runs on a worker thread; Tk widgets are touched **only** on the
  main thread, with results marshalled through `after(0, …)`;
* the GUI never blocks on the model.

`causal_conv1d` and `flash-linear-attention` are optional accelerator kernels.
Without them Transformers falls back to reference implementations — correct, but
slower. The timings above were measured on the fallback path.

---

## Safety and ethical notes

* Every employee in the database is **fictional**.
* The application only changes data inside its own SQLite database.
* No real account is disabled, no network is blocked, no file is deleted.
* Every response action is **simulated and written to the audit log**.
* Kev output is a **behavioural risk indicator that requires analyst review** —
  never proof of malicious intent, and never a basis for action against a person
  without human investigation.
* The Windows→CERT feature mapping is an application-specific adaptation,
  documented per feature, and is **not** a validated port of the model.
* Sentiment scoring is contextual only — never used to label or punish an
  employee.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `run.ps1` reports the Python version is unsupported | Kev requires `>=3.12,<3.14`. Point `-Python` at a 3.12 or 3.13 interpreter |
| `No Python interpreter found` | `python` is not on `PATH`; pass `-Python`, or write `.python-path` |
| `python` opens the Microsoft Store stub | Use `py main.py` |
| AI page: `Kev unavailable — the 'kev' package is not importable` | `pip install -e <kev-checkout>` |
| AI page: `feature_builder not found` | Set `KEV_REPO_PATH` to the Kev checkout root |
| AI page: `Kev loading…` for a long time | The first load pulls the base model; it needs a network connection once, or a local copy via `KEV_LOCAL_PATH` |
| Kev probabilities are all very low | The user has fewer than 10 days of history, so the baseline features are still zero. Let activity accumulate, or use the activity simulator, which backfills labelled history |
| A user is flagged and stays flagged | Expected. The model is baseline-aware and the threshold is deliberately high-precision; review the AI page detail view before acting |
| Windows Security log unavailable | The event-log monitor falls back to the Application log automatically |
| Legacy IsolationForest shows as unavailable | scikit-learn is optional and off by default; the rest of the app is unaffected |
| Out of VRAM | Set `KEV_DEVICE=cpu` |
| Need a clean start | Settings → Reset all data, or delete `insider_threat.db` |

---

## Known limitations

Honest list, in rough order of importance.

1. **The Windows→CERT mapping is a prototype and is not validated.** Four of the
   ten features are `degenerate` or `absent` on a single-machine deployment.
   Kev's probabilities here are **not** comparable to its published CERT metrics.
2. **Kev's precision is low by design.** The published operating point yields
   roughly 0.70 recall at roughly 0.08 precision on CERT — most alerts are
   expected to be false positives.
3. **Sparse history is the dominant early behaviour.** With fewer than 10 prior
   days, deviations are 0.0 by contract and every user looks similar.
4. **The rule engine's window is 60 minutes** while Kev reasons over a whole
   day, so the two naturally disagree on short timescales.
5. **`risk_history` grows without bound** — there is no retention job.
6. **Legacy IsolationForest is unverified on this machine** (a Windows
   Application Control policy blocks `scikit-learn`'s `_cd_fast` DLL). The
   application degrades gracefully, but that path has not been exercised here.
7. **The activity simulator's stored `source` values** remain `demo` /
   `demo_seed` in the database (they display as `simulated` in the UI); renaming
   them would need a data migration for no visible benefit.
8. **PDF export has no test coverage for pathological content.** It is verified
   against ReportLab 5.0.1 (`tests/test_pdf_report.py`) for normal, empty and
   non-ASCII data, but very wide tables will run past the page margin rather
   than paginating.
9. **Other pre-existing issues** not addressed here because they do not block
   the application: gamification double-insert and a radio-button `StringVar`
   bug; a duplicate re-emission in the event-log monitor; a fixed NTFS volume
   reported as USB; system32 paths treated as privilege elevation.

---

## License

Educational use only.
