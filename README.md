# EdgeSentinel

EdgeSentinel is a MadHacks 2026 prototype that watches synthetic telemetry from a fleet of simulated home routers. It combines per-router behavior features, anomaly scoring, incident handling, privacy checks, and an analyst dashboard.

**All data in this repository is synthetic.** The prototype is not connected to TDS routers and its results are not real-world accuracy claims.

## What runs locally

- `simulator/`: creates the synthetic router fleet, normal traffic, attacks, and harmless look-alikes.
- `detection/`: creates rolling features, scores routers, applies the decision table, and manages incidents.
- `app/engine.py`: advances the simulator, calls detection, saves rows to SQLite, and handles dashboard commands.
- `reporting/`: checks a privacy-filtered payload for leaks and generates an AI or template report.
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
$env:DEMO_OFFLINE = '1'
.\.venv\Scripts\python.exe -m reporting.reporter
```

`DEMO_OFFLINE=1` forces local template reports and makes zero OpenAI API calls. To enable AI reports, use `DEMO_OFFLINE=0` and set `OPENAI_API_KEY` in your local root `.env`. Use [the reporting settings example](reporting/.env.example) for the model and call limit. Settings exported in the reporter terminal take precedence over `.env`. If a privacy or budget check blocks a request, or the AI request fails, the worker uses a template.

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

## Saved rehearsal

Open **Saved rehearsal** in the dashboard and choose a scenario to view a previously generated report. The viewer shows the **Saved from rehearsal** badge, the original source and model, and the human review status. It reads validated fixtures from the repository and makes zero API calls. Current investigations and the live report count stay in **Live**.

## Privacy behavior in the current prototype

The reporting code builds its payload from an allowlist of approved summary fields. It stores an internal raw snapshot and token map, scans the prepared payload for private values, and stores the audit in SQLite. In AI mode, only the allowlisted payload that passes the check can be sent to OpenAI. The raw snapshot and token map stay in SQLite.

## Limitations

- The router telemetry and attack scenarios are synthetic.
- If the trained model bundle is missing, the detector integration stub is used.
- Evaluation results appear only after `models/eval_report.json` is produced.
- Real router telemetry, a security review, and real incident labels would be needed before drawing production conclusions.

## Team workflow

Keep work on a feature branch, pull the latest `main` before starting a new task, and push your branch so teammates can review it. Open a pull request into `main` when a change is ready. Do not force-push `main`.
