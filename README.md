# EdgeSentinel

EdgeSentinel is a MadHacks 2026 prototype that watches synthetic telemetry from a fleet of simulated home routers. It combines per-router behavior features, anomaly scoring, incident handling, privacy checks, and an analyst dashboard.

**All data in this repository is synthetic.** The prototype is not connected to TDS routers and its results are not real-world accuracy claims.

## What runs locally

- `simulator/`: creates the synthetic router fleet, normal traffic, attacks, and harmless look-alikes.
- `detection/`: creates rolling features, scores routers, applies the decision table, and manages incidents.
- `app/engine.py`: advances the simulator, calls detection, saves rows to SQLite, and handles dashboard commands.
- `reporting/`: prepares a privacy-filtered payload, checks it for leaks, and currently creates a template report.
- `app/dashboard.py`: reads the database and displays the fleet, recent activity, incidents, reports, and privacy audit.
- `live.db`: local SQLite data created when the programs run. It is ignored by Git.

Databricks is for offline storage, training, and evaluation. The live programs run on the laptop and do not need Databricks.

## Requirements

- Windows 10 or later
- Python 3.12
- Git

The required Python packages are listed in `requirements.txt`. The scikit-learn, pandas, and NumPy versions are fixed to match the training environment.

## Set up on Windows

Open PowerShell or the VS Code terminal in the repository folder, then run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use .\.venv\Scripts\python.exe for the commands below; it uses the project Python 3.12 environment.

## Check the local setup

Check that the database functions can create, write, read, queue, and reset records in a temporary database. This does not alter `live.db`:

```powershell
.\.venv\Scripts\python.exe -m app.db --selftest
```

Run the project checks:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Run the live demo

Start the three programs in **three separate terminals**, all opened in the repository folder. Keep each terminal open while the demo is running.

**Terminal 1 - engine**

```powershell
.\.venv\Scripts\python.exe -m app.engine
```

The engine warms up the simulator, creates or opens `live.db`, and advances one simulated minute per real second. It loads `models/edgesentinel_v2.joblib` when that file is present. If the file is absent, the detector uses its integration stub and prints a warning.

**Terminal 2 - report worker**

```powershell
.\.venv\Scripts\python.exe -m reporting.reporter
```

The current report worker uses the privacy allowlist and leak check, saves an audit, and creates a template report. It currently makes **no external AI call**; the audit marks the payload as prepared but not sent.

**Terminal 3 - dashboard**

```powershell
.\.venv\Scripts\python.exe -m streamlit run app/dashboard.py
```

Streamlit prints a local address in the terminal and normally opens it in your browser. The dashboard refreshes its live section every two seconds.

## Dashboard controls

The sidebar lets you select a router and queue a scenario for the engine:

- Botnet
- Start loud phase
- Fast or slow password guessing
- New smart device
- Forgot password
- Reset fleet

The fleet grid selects routers for the detail view. The dashboard shows recent counter charts, classifier scores, the latest incident and report, and the privacy audit. The Evaluation tab displays `models/eval_report.json` when that file is available.

The Reset fleet button clears the current demo rows and active incidents while keeping the simulator clock moving. Use it when preparing a clean run.

## Privacy behavior in the current prototype

The reporting code builds its payload from an allowlist of approved summary fields. It stores an internal raw snapshot and token map, scans the prepared payload for private values, and stores the audit in SQLite. The token map is not part of the prepared payload. The current report worker uses fallback templates and does not send the payload to an outside service.

## Limitations

- The router telemetry and attack scenarios are synthetic.
- If the trained model bundle is missing, the detector integration stub is used.
- The current report worker creates template reports; it does not call an external AI service.
- Evaluation results appear only after `models/eval_report.json` is produced.
- Real router telemetry, a security review, and real incident labels would be needed before drawing production conclusions.

## Team workflow

Keep work on a feature branch, pull the latest `main` before starting a new task, and push your branch so teammates can review it. Open a pull request into `main` when a change is ready. Do not force-push `main`.
