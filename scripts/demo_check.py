"""Demo timing check (P1.12): ticks until each demo incident opens and has a report.

    python -m scripts.demo_check                     # uses MODEL_PATH (default models/edgesentinel_v2.joblib)
    MODEL_PATH=stub python -m scripts.demo_check     # stub detector

Runs the REAL live pipeline headless (TICK_SECONDS=0), one throwaway SQLite file per
scenario so live.db is never touched:
    dashboard button -> commands table -> app.engine.process_tick (Fleet, features,
    detector, incidents, report queue) -> reporting.reporter.process_one (offline,
    template reports, no paid AI calls).
One tick = one simulated minute = one real second in the live demo.
Re-run after every model change and share the table.
"""
from __future__ import annotations

import logging
import os
import tempfile
import warnings
from pathlib import Path

os.environ["TICK_SECONDS"] = "0"
os.environ["DEMO_OFFLINE"] = "1"

from app import db, engine  # noqa: E402
from detection.detector import load_bundle  # noqa: E402
from detection.incidents import IncidentManager  # noqa: E402
from reporting.reporter import process_one  # noqa: E402
from simulator.fleet import Fleet  # noqa: E402
from simulator.households import INJECTION_DEVICE  # noqa: E402

# (router, dashboard command, what the demo needs)
SCENARIOS = [
    ("R-107", "botnet", "botnet incident during the quiet phase, then escalates on botnet_loud"),
    ("R-102", "new_device", "low advisory (unusual_benign), never an attack"),
    ("R-103", "brute_force_fast", "brute_force incident"),
    ("R-105", "brute_force_slow", "brute_force incident (harder)"),
    ("R-106", "forgot_password", "no incident, or a low advisory"),
    ("R-104", "brute_force_fast", "incident; injection device absent from the AI payload"),
]
MAX_TICKS = 60       # live botnet goes loud by itself after 60 quiet minutes
HEALTHY_TICKS = 2
LOUD_AFTER_OPEN = 5  # press "Start loud phase" this many ticks after the botnet incident opens


def run(router: str, scenario: str, bundle: dict, folder: Path) -> dict:
    db.DB_PATH = folder / f"demo_check_{router}_{scenario}.db"
    db.init_db()
    fleet = Fleet(n_routers=12, seed=7)
    buffer = engine.warmup_buffer(fleet)
    db.insert_records(engine.chart_seed_records(buffer))
    incidents = IncidentManager()
    out = {"opened": None, "type": "-", "severity": "-", "report": None, "report_source": "-",
           "loud_trigger": None, "escalated": None, "esc_severity": "-", "injection": "-"}

    for tick in range(-HEALTHY_TICKS, MAX_TICKS + 30):
        if tick == 0:
            db.insert_command(scenario, router)          # what the dashboard button does
        if scenario == "botnet" and out["loud_trigger"] is None and (
                (out["opened"] is not None and tick == out["opened"] + LOUD_AFTER_OPEN) or tick == 45):
            db.insert_command("botnet_loud", router)
            out["loud_trigger"] = tick
        buffer, incidents = engine.process_tick(fleet, buffer, bundle, incidents)
        while process_one(db):                           # the reporter drains its queue
            pass

        inc = db.open_or_latest_incident(router) if tick >= 0 else None
        if inc is not None:
            if out["opened"] is None:
                out.update(opened=tick, type=inc["incident_type"], severity=inc["severity"])
            if out["report"] is None:
                rep = db.latest_report(inc["incident_id"])
                if rep is not None:
                    out.update(report=tick, report_source=rep["source"])
                    audit = db.latest_audit(inc["incident_id"])
                    if router == "R-104" and audit is not None:
                        sent = str(audit.get("sent_payload"))
                        out["injection"] = "LEAK" if INJECTION_DEVICE in sent else "absent (ok)"
            if out["loud_trigger"] is not None and out["escalated"] is None and inc["version"] >= 2:
                out.update(escalated=tick, esc_severity=inc["severity"])

        done = out["report"] is not None and (scenario != "botnet" or out["escalated"] is not None)
        if done or (tick >= MAX_TICKS and scenario != "botnet"):
            break
    return out


def main():
    logging.disable(logging.INFO)
    path = os.getenv("MODEL_PATH", "models/edgesentinel_v2.joblib")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        bundle = load_bundle(path)
    version = bundle.get("version", "?")
    print(f"model: {path} (version {version}); pipeline: app.engine + reporting.reporter (offline)")
    if version == "stub":
        print("WARNING: stub detector - only STUB_ATTACK_ROUTERS (default R-107) ever flags. "
              "These timings mean nothing until a real bundle exists.")
    print(f"{'router':7} {'scenario':17} {'opens@':>6} {'type':15} {'sev':8} {'report@':>7} "
          f"{'loud@':>5} {'esc@':>5} {'esc_sev':8} expected")
    f = lambda v: "-" if v is None else str(v)
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for router, scenario, expected in SCENARIOS:
            r = run(router, scenario, bundle, Path(tmp))
            print(f"{router:7} {scenario:17} {f(r['opened']):>6} {str(r['type']):15} {str(r['severity']):8} "
                  f"{f(r['report']):>7} {f(r['loud_trigger']):>5} {f(r['escalated']):>5} "
                  f"{str(r['esc_severity']):8} {expected}")
            if router == "R-104":
                print(f"        injection device in the AI payload: {r['injection']}")
    print("ticks = simulated minutes after the button press (1 tick = 1 s live). '-' = never within the run.")


if __name__ == "__main__":
    main()
