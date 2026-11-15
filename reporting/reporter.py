"""Maksym's privacy + AI/fallback reporter, blueprint steps 10.3.4 through 10.3.7.

The live adapter is Person 4's app.db. --example uses memory only and defaults
to offline.
"""

import argparse
from copy import deepcopy
import importlib
import json
import logging
from pathlib import Path
import time

from reporting.llm import ReportWriter, load_settings


logger = logging.getLogger(__name__)


def process_one(db, writer: ReportWriter | None = None) -> bool:
    """Claim one request and save an AI or template report via the section 9 adapter.

    Return False for an empty queue, True for a handled request (done or failed).
    Claiming and save_report idempotency must be implemented by the DB owner.
    The long-running worker must pass the SAME writer each time to retain its
    budget. Omitting it creates an offline-only writer for backwards compatibility.
    """

    request = db.claim_report_request()
    if request is None:
        return False
    incident_id, version = request["incident_id"], request["version"]
    started = time.perf_counter()
    try:
        get_report_inputs = getattr(db, "get_report_inputs", None)
        if get_report_inputs is None:
            incident = db.get_incident(incident_id)
        else:
            incident, records = get_report_inputs(incident_id, version)
        if incident["incident_id"] != incident_id or incident["version"] != version:
            raise ValueError("Requested incident version is unavailable")
        if get_report_inputs is None:
            records = db.recent_records(incident["router_id"], 30)
        if writer is None:
            writer = ReportWriter({"DEMO_OFFLINE": "1", "MAX_AI_CALLS": "20"})
        result = writer.generate(incident, records, save_audit=db.save_audit)
        for warning in result.warnings:
            logger.warning("Report validation warning: %s", warning)
        db.save_report(
            incident_id=incident_id,
            version=version,
            source=result.source,
            model=result.model,
            latency_ms=round((time.perf_counter() - started) * 1000),
            error=result.error,
            report=result.report.model_dump(),
        )
        db.finish_report_request(incident_id, version, "done")
    except Exception as error:
        # ValidationError text can contain private input. Log the error type,
        # not its message, raw incident, or traceback.
        logger.error("Report request failed (%s)", type(error).__name__)
        db.finish_report_request(incident_id, version, "failed")
    return True


class _ExampleDB:
    """One synthetic request in memory, not a replacement SQLite database."""

    def __init__(self):
        root = Path(__file__).resolve().parents[1]
        self.incident = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
        self.records = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
        self.status = "pending"
        self.saved_report = None
        self.saved_audit = None

    def claim_report_request(self):
        if self.status != "pending":
            return None
        self.status = "in_progress"
        return {"incident_id": self.incident["incident_id"], "version": 1}

    def get_incident(self, incident_id):
        if incident_id != self.incident["incident_id"]:
            raise KeyError("Unknown example incident")
        return deepcopy(self.incident)

    def save_report(self, **fields):
        self.saved_report = deepcopy(fields)

    def recent_records(self, router_id, minutes):
        if router_id != self.incident["router_id"] or minutes != 30:
            raise ValueError("Unexpected example record request")
        return deepcopy(self.records)

    def save_audit(self, audit):
        self.saved_audit = deepcopy(audit)

    def finish_report_request(self, incident_id, version, status):
        if incident_id != self.incident["incident_id"] or version != 1:
            raise ValueError("Unknown example request")
        self.status = status


def main() -> None:
    parser = argparse.ArgumentParser(description="Privacy-aware AI/fallback report queue worker")
    parser.add_argument("--example", action="store_true", help="Run one synthetic request in memory")
    parser.add_argument("--once", action="store_true", help="Check for at most one request, then exit")
    parser.add_argument("--send", action="store_true", help="With --example only: opt into one paid Luna request")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.send and not args.example:
        parser.error("--send is only for the one-request --example demo")

    if args.example:
        db = _ExampleDB()
        settings = load_settings()
        settings["DEMO_OFFLINE"] = "0" if args.send else "1"
        settings["MAX_AI_CALLS"] = "1"
        writer = ReportWriter(settings)
        process_one(db, writer)
        if db.status != "done":
            raise SystemExit("Example failed; inspect the error type above")
        print(json.dumps({
            "mode": "in_memory_demo",
            "queue_status": db.status,
            "source": db.saved_report["source"],
            "error": db.saved_report["error"],
            "severity": db.saved_report["report"]["severity"],
            "likely_category": db.saved_report["report"]["likely_category"],
            "evidence_count": len(db.saved_report["report"]["evidence"]),
            "audit_saved": db.saved_audit is not None,
            "leak_check_passed": db.saved_audit["leak_check"]["passed"],
            "privacy_blocked": db.saved_audit["leak_check"]["blocked"],
            "payload_status": db.saved_audit["leak_check"]["payload_status"],
            "values_checked": db.saved_audit["leak_check"]["values_checked"],
            "second_queue_check_empty": not process_one(db, writer),
            "database_file_created": False,
            "api_requests_attempted": writer.calls,
        }, indent=2))
        return

    try:
        db = importlib.import_module("app.db")
    except ModuleNotFoundError as error:
        if error.name not in ("app", "app.db"):
            raise
        parser.error("app/db.py is not available yet. Use --example for the in-memory demonstration.")
    for name in ("claim_report_request", "get_incident", "recent_records", "save_audit", "save_report", "finish_report_request"):
        if not callable(getattr(db, name, None)):
            parser.error(f"app.db is missing required function: {name}")
    db.init_db()
    # One writer for the entire process: never reset its counters per queue row.
    writer = ReportWriter(load_settings())
    if args.once:
        process_one(db, writer)
        return
    try:
        while True:
            if not process_one(db, writer):
                time.sleep(2)
    except KeyboardInterrupt:
        logger.info("Reporter stopped")


if __name__ == "__main__":
    main()
