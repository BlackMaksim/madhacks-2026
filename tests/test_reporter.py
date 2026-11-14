"""Queue-worker behavior through the blueprint DB interface, without SQLite."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from reporting.reporter import process_one
from reporting.schema import IncidentReport


@pytest.fixture
def db():
    path = Path(__file__).resolve().parents[1] / "contracts/examples/ai_input.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    adapter = Mock()
    adapter.claim_report_request.side_effect = [
        {"incident_id": "INC-0007", "version": 1}, None,
    ]
    adapter.get_incident.return_value = {
        "incident_id": "INC-0007", "router_id": "R-107", "version": 1,
        "incident_type": "botnet", "severity": "high", "evidence": payload["evidence"],
    }
    return adapter


def test_empty_queue_does_not_generate_report(db):
    db.claim_report_request.side_effect = [None]
    assert process_one(db) is False
    db.get_incident.assert_not_called()
    db.save_report.assert_not_called()
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
    assert "ValidationError" in caplog.text
    assert marker not in caplog.text


def test_save_failure_does_not_mark_request_done(db, caplog):
    db.save_report.side_effect = RuntimeError("private database details")
    process_one(db)
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")
    assert "private database details" not in caplog.text
