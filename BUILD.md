# BUILD.md — the shortest path to a running app

Tested on Windows 11 with Python 3.13.

## 1. An interpreter (3.12 or 3.13 — not 3.11, not 3.14)

Kev declares `requires-python = ">=3.12,<3.14"`, and a few GUI f-strings use
3.12-only syntax.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If your environment already exists somewhere else (this machine uses
`C:\Users\gonch\OneDrive\Documents\Intership\kev-env`), you do not need a new
one. Just record it so `run.ps1` finds it:

```powershell
Set-Content .python-path "C:\Users\gonch\OneDrive\Documents\Intership\kev-env\Scripts\python.exe"
```

`.python-path` is in `.gitignore` — it is machine-local.

## 2. The application's dependencies

```powershell
pip install -r requirements.txt
```

`scikit-learn` and `joblib` are listed for the legacy IsolationForest, which
is **off by default**; the app runs without them. Everything else is required.

## 3. The Kev package and its feature builder

Two separate things:

```powershell
# the importable `kev` module
pip install -e "C:\path\to\kev-checkout"

# feature_builder.py sits at the checkout ROOT, outside the package, so it is
# not installed by that command. Point the app at it:
$env:KEV_REPO_PATH = "C:\path\to\kev-checkout"
```

`KEV_REPO_PATH` is auto-probed at `C:\Users\gonch\OneDrive\Documents\Intership\kev`
and at `..\kev` / `.\kev` relative to the project, so on this machine it may
already resolve without being set. The Settings page shows which path was
found.

## 4. Verify

```powershell
python scripts\verify_build.py
```

Twelve checks: interpreter, imports, database, schema, config, monitors, rule
engine, alert/incident/audit wiring, and two that actually load the Kev
checkpoint and score a synthetic user-day. Exit code 0 means the build is
sound. On a CPU-only machine the two model checks report `SKIP`, not `FAIL`.

The first model check downloads the base model (~1.7 GB) if it is not cached.
After that, loading takes roughly 10-18 s and each prediction ~0.2 s.

Skip the model entirely:

```powershell
python scripts\verify_build.py --skip-model
python scripts\smoke_test_kev.py       # optional: score two synthetic user-days
```

## 5. Run

```powershell
.\run.ps1
```

That is the whole thing. `run.ps1` resolves the interpreter (see `.NOTES` in
the script for the full order), refuses to launch on a Python version the
project does not support, runs the verification, and then starts `main.py`.

```powershell
.\run.ps1 -SkipVerify              # launch without verifying
.\run.ps1 -SkipModel               # verify, but do not load the checkpoint
.\run.ps1 -Python C:\path\to\python.exe
```

The GUI appears immediately. Kev loads on a background thread — the AI page
shows **Kev loading…** until it is ready, and the rest of the app is usable in
the meantime.

---

## Offline deployment

True offline operation needs the checkpoint **and** its base model already on
disk. Downloading once and caching is not the same as deploying offline, and
the application does not redesign itself around network access — if the model
cannot be reached, the AI page reports `Kev unavailable` and everything else
keeps working.

```powershell
# once, while online
huggingface-cli download joshnavardhan/kev-cert-r42-v3 --local-dir D:\models\kev-cert-r42-v3
huggingface-cli download Qwen/Qwen3.5-0.8B-Base          --local-dir D:\models\qwen3.5-0.8b-base

# then, offline
$env:KEV_LOCAL_PATH  = "D:\models\kev-cert-r42-v3"
$env:HF_HUB_OFFLINE  = "1"
```

`KEV_LOCAL_PATH` wins over `KEV_MODEL_ID` whenever the directory exists. The
checkpoint is loaded once per run and is never retrained.

## GPU

CUDA is used when `torch.cuda.is_available()` is true; otherwise the app falls
back to CPU automatically — slower, but functional. The measured footprint on
an RTX 5060 Laptop was ~3.1 GB VRAM and ~0.2 s per prediction.

`causal_conv1d` and `flash-linear-attention` are optional accelerator kernels.
Without them Transformers falls back to reference implementations, which is
what the timings above were measured on.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `run.ps1` says the Python version is not supported | Use a 3.12 or 3.13 interpreter (`-Python`, or `.python-path`) |
| `No Python interpreter found` | `python` is not on `PATH`; pass `-Python` |
| `ModuleNotFoundError: kev` | `pip install -e <kev-checkout>` |
| `feature_builder not found` | Set `KEV_REPO_PATH` to the checkout root |
| `Kev loading…` never finishes | First load needs the base model; check the network, or use `KEV_LOCAL_PATH` |
| Out of VRAM | Set `KEV_DEVICE=cpu` |
| Windows Defender flags a monitor | The file/process/network monitors are read-only observers; allow the process |
| Want a clean database | Settings → Reset demo data, or delete `insider_threat.db` |
