"""Offline escalation rehearsal using three hand-authored snapshots.

No .env, API, database, or detector is used. This checks reporting behavior, not
whether a real detector would produce these escalation events.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import json

from reporting.llm import ReportWriter
from reporting.quality_cases import QualityCase, build_quality_cases


def build_escalation_cases() -> list[QualityCase]:
    cases = {case.name: case for case in build_quality_cases()}
    snapshots = [deepcopy(cases["botnet_quiet"]), deepcopy(cases["botnet_loud"]), deepcopy(cases["botnet_loud"])]
    original_last = datetime.fromisoformat(snapshots[0].incident["last_ts"])
    for version, case in enumerate(snapshots, start=1):
        case.name = f"botnet_version_{version}"
        case.incident.update(incident_id="INC-ESC-0001", router_id="R-107", version=version)
        case.incident["last_ts"] = (original_last + timedelta(minutes=10 * (version - 1))).isoformat()
        for row in case.records:
            row["router_id"] = "R-107"
            row["ts"] = (datetime.fromisoformat(row["ts"]) + timedelta(minutes=10 * (version - 1))).isoformat()
        if version == 3:
            # Same critical severity with a further increase in measured volume.
            for item in case.incident["evidence"]:
                item["observed"] *= 2
                item["times_usual"] = round((item["observed"] + 1) / (item["usual"] + 1), 1)
                for row in case.records:
                    row[item["signal"]] *= 2
            case.incident["trend_per_5_min"] = {
                signal: [sum(row[signal] for row in case.records[:5]), sum(row[signal] for row in case.records[5:])]
                for signal in case.incident["trend_per_5_min"]
            }
        case.review_focus = "Compare with the last available measurement snapshot without copying old AI prose."
    return snapshots


def main() -> None:
    writer = ReportWriter({"DEMO_OFFLINE": "1", "MAX_AI_CALLS": "3"})
    rows = []
    for case in build_escalation_cases():
        result = writer.generate(case.incident, case.records)
        payload = json.loads(result.audit["sent_payload"])
        rows.append({
            "version": case.incident["version"], "severity": result.report.severity,
            "source": result.source, "error": result.error,
            "previous_context_available": payload.get("previous_summary", {}).get("available", False),
            "behavior_explanation": result.report.behavior_explanation,
        })
    print(json.dumps({"mode": "offline_escalation_rehearsal", "api_requests_attempted": writer.calls, "results": rows}, indent=2))


if __name__ == "__main__":
    main()
