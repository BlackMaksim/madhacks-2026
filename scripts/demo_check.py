"""Demo timing check (P1.12): how many ticks until each demo incident opens and has a report.

    python -m scripts.demo_check                     # uses MODEL_PATH (default models/edgesentinel_v2.joblib)
    MODEL_PATH=stub python -m scripts.demo_check     # stub detector

Runs the engine's pipeline headless with TICK_SECONDS=0: Fleet -> build_features ->
score_rows -> IncidentManager, then the offline report path (build_ai_payload +
fallback_report, same as DEMO_OFFLINE=1). One tick = one simulated minute = one
real second in the live demo. Re-run after every model change and share the table.
"""
from __future__ import annotations

import os
import warnings

import pandas as pd

from detection import config as C
from detection.detector import load_bundle, score_rows
from detection.features import build_features
from detection.incidents import IncidentManager
from simulator.fleet import Fleet
from simulator.households import INJECTION_DEVICE

os.environ.setdefault("TICK_SECONDS", "0")

# (router, scenario, what the demo needs)
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


def make_report(incident: dict, recent: list[dict]):
    """Offline report path. Returns (ok, detail, payload_text)."""
    try:
        from reporting.fallback import fallback_report
        from reporting.privacy import build_ai_payload, serialize_payload
        payload, _audit = build_ai_payload(incident, recent)
        fallback_report(payload)
        return True, "fallback report", serialize_payload(payload)
    except Exception as e:  # report what broke instead of hiding it
        return False, f"{type(e).__name__}: {e}"[:120], ""


def run(router: str, scenario: str, bundle: dict) -> dict:
    fleet = Fleet(n_routers=12, seed=7)
    warm = pd.DataFrame(fleet.warmup(hours=24))
    buf = warm[warm["router_id"] == router].tail(C.LIVE_BUFFER_MINUTES)
    raw = buf.to_dict("records")
    mgr = IncidentManager()
    out = {"router": router, "scenario": scenario, "opened": None, "type": "-", "severity": "-",
           "report": None, "report_detail": "", "loud_trigger": None, "escalated": None,
           "esc_severity": "-", "injection_leak": "-"}

    for tick in range(-HEALTHY_TICKS, MAX_TICKS + 30):
        if tick == 0:
            fleet.trigger(router, scenario)
        # botnet: press "Start loud phase" 5 ticks after the incident opens (or at tick 45)
        if scenario == "botnet" and out["loud_trigger"] is None and (
                (out["opened"] is not None and tick == out["opened"] + 5) or tick == 45):
            fleet.trigger(router, "botnet_loud")
            out["loud_trigger"] = tick
        rec = next(r for r in fleet.step() if r["router_id"] == router)
        raw.append(rec)
        buf = pd.concat([buf, pd.DataFrame([rec])], ignore_index=True).tail(C.LIVE_BUFFER_MINUTES)
        feat = build_features(buf).tail(1)
        score = score_rows(bundle, feat).iloc[0].to_dict()
        event = mgr.update(score, feat.iloc[0].to_dict())
        if not event or tick < 0:
            if tick >= MAX_TICKS and scenario != "botnet":
                break
            continue
        inc = event["incident"]
        if event["event"] == "opened" and out["opened"] is None:
            out.update(opened=tick, type=inc.get("incident_type"), severity=inc.get("severity"))
            ok, detail, text = make_report(inc, raw[-30:])
            out["report"] = tick if ok else None
            out["report_detail"] = detail
            if router == "R-104" and text:
                out["injection_leak"] = "LEAK" if INJECTION_DEVICE in text else "absent (ok)"
        elif event["event"] == "escalated" and out["loud_trigger"] is not None and out["escalated"] is None:
            out.update(escalated=tick, esc_severity=inc.get("severity"))
        if scenario == "botnet" and out["escalated"] is not None:
            break
        if scenario != "botnet" and out["opened"] is not None:
            break
    return out


def main():
    path = os.getenv("MODEL_PATH", "models/edgesentinel_v2.joblib")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        bundle = load_bundle(path)
    version = bundle.get("version", "?")
    print(f"model: {path} (version {version})")
    if version == "stub":
        print("WARNING: stub detector - only STUB_ATTACK_ROUTERS (default R-107) ever flags. "
              "These timings mean nothing until a real bundle exists.")
    print(f"{'router':7} {'scenario':17} {'opens@':>6} {'type':15} {'sev':8} {'report@':>7} "
          f"{'loud@':>5} {'esc@':>5} {'esc_sev':8} expected")
    for router, scenario, expected in SCENARIOS:
        r = run(router, scenario, bundle)
        f = lambda v: "-" if v is None else str(v)
        print(f"{router:7} {scenario:17} {f(r['opened']):>6} {str(r['type']):15} {str(r['severity']):8} "
              f"{f(r['report']):>7} {f(r['loud_trigger']):>5} {f(r['escalated']):>5} "
              f"{str(r['esc_severity']):8} {expected}")
        if r["report_detail"] and r["report"] is None:
            print(f"        report failed: {r['report_detail']}")
        if router == "R-104":
            print(f"        injection device in AI payload: {r['injection_leak']}")
    print("ticks = simulated minutes after the trigger (1 tick = 1 s live). '-' = never within the run.")


if __name__ == "__main__":
    main()
