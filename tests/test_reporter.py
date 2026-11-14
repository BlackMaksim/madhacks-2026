"""Queue-worker behavior through the blueprint DB interface, without SQLite."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from reporting.reporter import process_one
from reporting import reporter
from reporting.schema import IncidentReport


@pytest.fixture
def db():
    root = Path(__file__).resolve().parents[1]
    adapter = Mock()
    adapter.claim_report_request.side_effect = [
        {"incident_id": "INC-0007", "version": 1}, None,
    ]
    adapter.get_incident.return_value = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
    adapter.recent_records.return_value = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
    return adapter


def test_empty_queue_does_not_generate_report(db):
    db.claim_report_request.side_effect = [None]
    assert process_one(db) is False
    db.get_incident.assert_not_called()
    db.save_report.assert_not_called()
    db.save_audit.assert_not_called()
    db.finish_report_request.assert_not_called()


def test_request_saves_valid_fallback_then_finishes(db):
    original = deepcopy(db.get_incident.return_value)
    assert process_one(db) is True
    saved = db.save_report.call_args.kwargs
    assert saved["incident_id"] == "INC-0007"
    assert saved["version"] == 1
    assert saved["source"] == "fallback"
    assert saved["model"] is None
    assert saved["error"] is None
    assert saved["latency_ms"] >= 0
    assert IncidentReport.model_validate(saved["report"]).severity == "high"
    db.recent_records.assert_called_once_with("R-107", 30)
    audit = db.save_audit.call_args.args[0]
    assert audit["leak_check"]["passed"]
    assert audit["leak_check"]["api_call_made"] is False
    assert audit["leak_check"]["payload_status"] == "prepared_not_sent"
    assert "Jordan Miller" not in audit["sent_payload"]
    assert audit["raw_snapshot"]["records"][0]["customer_name"] == "Jordan Miller"
    methods = [call[0] for call in db.method_calls]
    assert methods.index("save_audit") < methods.index("save_report") < methods.index("finish_report_request")
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "done")
    assert db.get_incident.return_value == original
    assert process_one(db) is False
    db.save_report.assert_called_once()


def test_newer_incident_is_not_silently_saved_as_old_version(db):
    db.get_incident.return_value["version"] = 2
    assert process_one(db) is True
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")


def test_wrong_incident_is_rejected(db):
    db.get_incident.return_value["incident_id"] = "INC-OTHER"
    process_one(db)
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")


def test_invalid_evidence_is_failed_without_logging_private_input(db, caplog):
    marker = "private-name-do-not-log"
    db.get_incident.return_value["evidence"][0]["signal"] = marker
    process_one(db)
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")
    assert "ValueError" in caplog.text
    assert marker not in caplog.text


def test_save_failure_does_not_mark_request_done(db, caplog):
    db.save_report.side_effect = RuntimeError("private database details")
    process_one(db)
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")
    assert "private database details" not in caplog.text


def test_audit_failure_prevents_report_creation(db):
    db.save_audit.side_effect = RuntimeError("internal audit unavailable")
    process_one(db)
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")


def test_leak_is_recorded_and_only_safe_template_fields_are_used(db, monkeypatch):
    original_builder = reporter.build_ai_payload

    def compromised_builder(incident, records):
        payload, audit = original_builder(incident, records)
        payload["accidental_private_field"] = records[0]["customer_name"]
        return payload, audit

    monkeypatch.setattr(reporter, "build_ai_payload", compromised_builder)
    process_one(db)
    audit = db.save_audit.call_args.args[0]
    assert audit["leak_check"]["blocked"] is True
    assert audit["leak_check"]["passed"] is False
    assert audit["leak_check"]["api_call_made"] is False
    saved = db.save_report.call_args.kwargs
    assert saved["source"] == "fallback"
    assert saved["model"] is None
    assert saved["error"] == "privacy_check_blocked"
    assert "Jordan Miller" not in json.dumps(saved["report"])
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "done")


def test_missing_raw_records_fails_without_inventing_context(db):
    db.recent_records.return_value = []
    process_one(db)
    db.save_audit.assert_not_called()
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")
