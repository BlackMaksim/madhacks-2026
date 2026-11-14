"""Maksym's fallback-only reporter, blueprint step 10.3.4.

The live adapter is Person 4's app.db. --example uses memory only. Privacy
auditing, API calls, queue recovery, and version snapshots are later integration
steps; this module does not claim to implement them yet.
"""

import argparse
from copy import deepcopy
import importlib
import json
import logging
from pathlib import Path
import time

from reporting.fallback import fallback_report


logger = logging.getLogger(__name__)


def process_one(db) -> bool:
    """Claim one request and save a fallback report using the section 9 adapter.

    Return False for an empty queue, True for a handled request (done or failed).
    Claiming and save_report idempotency must be implemented by the DB owner.
    """

    request = db.claim_report_request()
    if request is None:
        return False
    incident_id, version = request["incident_id"], request["version"]
    started = time.perf_counter()
    try:
        incident = db.get_incident(incident_id)
        if incident["incident_id"] != incident_id or incident["version"] != version:
            raise ValueError("Requested incident version is unavailable")
        # Temporary local-only projection for the fallback milestone. No raw
        # records or arbitrary incident prose are passed to the report builder.
        # The full privacy.build_ai_payload + audit replaces this in step 10.3.5.
        payload = {
            "detector": {
                "incident_type": incident["incident_type"],
                "severity": incident["severity"],
            },
            "evidence": [
                {key: item[key] for key in ("signal", "observed", "usual")}
                for item in incident["evidence"]
            ],
        }
        report = fallback_report(payload)
        db.save_report(
            incident_id=incident_id,
            version=version,
            source="fallback",
            model=None,
            latency_ms=round((time.perf_counter() - started) * 1000),
            error=None,
            report=report.model_dump(),
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
        path = Path(__file__).resolve().parents[1] / "contracts/examples/ai_input.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.incident = {
            "incident_id": "INC-DEMO-0001",
            "router_id": "R-107",
            "version": 1,
            "incident_type": payload["detector"]["incident_type"],
            "severity": payload["detector"]["severity"],
            "evidence": payload["evidence"],
        }
        self.status = "pending"
        self.saved_report = None

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

    def finish_report_request(self, incident_id, version, status):
        if incident_id != self.incident["incident_id"] or version != 1:
            raise ValueError("Unknown example request")
        self.status = status


def main() -> None:
    parser = argparse.ArgumentParser(description="Fallback-only report queue worker")
    parser.add_argument("--example", action="store_true", help="Run one synthetic request in memory")
    parser.add_argument("--once", action="store_true", help="Check for at most one request, then exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.example:
        db = _ExampleDB()
        process_one(db)
        if db.status != "done":
            raise SystemExit("Example failed; inspect the error type above")
        print(json.dumps({
            "mode": "in_memory_demo",
            "queue_status": db.status,
            "source": db.saved_report["source"],
            "severity": db.saved_report["report"]["severity"],
            "likely_category": db.saved_report["report"]["likely_category"],
            "evidence_count": len(db.saved_report["report"]["evidence"]),
            "second_queue_check_empty": not process_one(db),
            "database_file_created": False,
            "api_calls": 0,
        }, indent=2))
        return

    try:
        db = importlib.import_module("app.db")
    except ModuleNotFoundError as error:
        if error.name not in ("app", "app.db"):
            raise
        parser.error("app/db.py is not available yet. Use --example for the in-memory demonstration.")
    for name in ("claim_report_request", "get_incident", "save_report", "finish_report_request"):
        if not callable(getattr(db, name, None)):
            parser.error(f"app.db is missing required function: {name}")
    if args.once:
        process_one(db)
        return
    try:
        while True:
            if not process_one(db):
                time.sleep(2)
    except KeyboardInterrupt:
        logger.info("Reporter stopped")


if __name__ == "__main__":
    main()
