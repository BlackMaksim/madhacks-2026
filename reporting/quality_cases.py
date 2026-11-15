"""Six deterministic, hand-authored reporting fixtures from blueprint 10.3.8.

These are NOT detector predictions or an accuracy benchmark. Each fixture has
ten synthetic minute records consistent with its supplied evidence totals.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path


@dataclass
class QualityCase:
    name: str
    incident: dict
    records: list[dict]
    review_focus: str


def build_quality_cases() -> list[QualityCase]:
    root = Path(__file__).resolve().parents[1]
    base_incident = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
    base_record = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))[0]
    specifications = [
        ("botnet_quiet", "botnet", "high", "botnet", {"dns_failures": (41, 3), "new_domains": (33, 4), "new_dest_ips": (14, 3)},
         "Explain the suspected pattern without claiming an established infection or an observed traffic flood."),
        ("botnet_loud", "botnet", "critical", "botnet", {"outbound_conns": (3200, 180), "unique_dest_ips": (1800, 100), "kb_out": (6500, 2000)},
         "Use the loud-phase flag and elevated connection counts; retain human verification before isolation."),
        ("brute_force_fast", "brute_force", "medium", "brute_force", {"failed_logins_wan": (200, 1), "login_sources": (10, 1)},
         "Describe guessing attempts without inventing a successful login."),
        ("brute_force_slow_success", "brute_force", "high", "brute_force", {"failed_logins_wan": (30, 1), "login_sources": (10, 1)},
         "Mention the success-after-failures flag as a reason to investigate, not proof the attacker gained access."),
        ("new_device", "unusual_benign", "low", "benign_unusual", {"new_domains": (40, 4), "new_dest_ips": (30, 3)},
         "Recognize the new-device context and harmless advisory; avoid alarmist compromise language."),
        ("unknown_anomaly", "unknown_anomaly", "medium", "normal", {"outbound_conns": (900, 100), "new_dest_ips": (60, 3)},
         "Keep the cause unknown; do not force an attack label from anomaly percentile alone."),
    ]
    cases = []
    for index, (name, kind, severity, predicted, measurements, focus) in enumerate(specifications, start=1):
        incident = deepcopy(base_incident)
        incident.update(incident_id=f"INC-QA-{index:04d}", router_id=f"R-{100 + index}", version=1,
                        incident_type=kind, severity=severity)
        incident["flags"] = {
            "new_device_last_60_min": name == "new_device",
            "success_after_failed_logins": name == "brute_force_slow_success",
            "loud_phase_signature": name == "botnet_loud",
        }
        verdict = "unusual_benign" if kind == "unusual_benign" else "unknown_anomaly" if kind == "unknown_anomaly" else "known_attack"
        incident["verdict_counts"] = {verdict: 5}
        probabilities = {"normal": 0.03, "benign_unusual": 0.03, "brute_force": 0.04, "botnet": 0.03}
        probabilities[predicted] = 1 - sum(value for key, value in probabilities.items() if key != predicted)
        if kind == "unknown_anomaly":
            probabilities = {"normal": 0.48, "benign_unusual": 0.18, "brute_force": 0.16, "botnet": 0.18}
        incident["detector"].update(predicted_class=predicted, class_probs=probabilities, model_version="hand_authored_reporting_fixture")
        incident["evidence"] = [
            {"signal": signal, "window_min": 10, "observed": observed, "usual": usual,
             "times_usual": round((observed + 1) / (usual + 1), 1)}
            for signal, (observed, usual) in measurements.items()
        ]
        records = []
        latest = datetime.fromisoformat(incident["last_ts"])
        for minute in range(10):
            row = deepcopy(base_record)
            row.update(router_id=incident["router_id"], ts=(latest - timedelta(minutes=9 - minute)).isoformat(),
                       failed_logins=0, failed_logins_wan=0, successful_logins=0, login_sources=0,
                       outbound_conns=20, unique_dest_ips=10, new_dest_ips=0, dns_queries=30,
                       dns_failures=0, new_domains=0, kb_out=200, devices=11, new_devices=0,
                       login_src_ips=[], usernames_tried=[])
            for signal, (observed, _) in measurements.items():
                row[signal] = observed // 10 + int(minute < observed % 10)
            if kind == "brute_force":
                row["failed_logins"] = row["failed_logins_wan"]
                source = minute % 2 if name == "brute_force_fast" else minute
                row["login_src_ips"] = [f"203.0.113.{10 + source}"]
                row["usernames_tried"] = ["admin", "root"]
            if name == "brute_force_slow_success" and minute == 9:
                row["successful_logins"] = 1
            if name == "botnet_loud":
                row["new_dest_ips"] = 150
            if name == "new_device":
                row["devices"] = 12
                row["new_devices"] = int(minute == 0)
                row["device_names"].append("Backyard-Camera")
            row["unique_dest_ips"] = max(row["unique_dest_ips"], row["new_dest_ips"])
            row["outbound_conns"] = max(row["outbound_conns"], row["unique_dest_ips"])
            records.append(row)
        incident["trend_per_5_min"] = {
            signal: [sum(row[signal] for row in records[:5]), sum(row[signal] for row in records[5:])]
            for signal in measurements
        }
        incident["login_summary"] = {
            "failed_outside_logins_10min": sum(row["failed_logins_wan"] for row in records),
            "distinct_outside_sources_10min": len({value for row in records for value in row["login_src_ips"]}),
        }
        cases.append(QualityCase(name, incident, records, focus))
    return cases
