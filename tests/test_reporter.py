"""Queue-worker behavior through the blueprint DB interface, without SQLite."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from reporting.reporter import process_one
from reporting import llm
from reporting.llm import ReportWriter
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
    assert saved["error"] == "offline_mode"
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
    original_builder = llm.build_ai_payload

    def compromised_builder(incident, records):
        payload, audit = original_builder(incident, records)
        payload["accidental_private_field"] = records[0]["customer_name"]
        return payload, audit

    monkeypatch.setattr(llm, "build_ai_payload", compromised_builder)
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


@pytest.fixture
def api_writer():
    root = Path(__file__).resolve().parents[1]
    report = IncidentReport.model_validate_json((root / "contracts/examples/report.json").read_text(encoding="utf-8"))
    factory = MagicMock()
    factory.return_value.__enter__.return_value.responses.parse.return_value = SimpleNamespace(
        status="completed", output_parsed=report, usage=None,
    )
    writer = ReportWriter({
        "OPENAI_API_KEY": "synthetic-test-key-not-real", "OPENAI_MODEL": "gpt-6-luna",
        "DEMO_OFFLINE": "0", "MAX_AI_CALLS": "20",
    }, client_factory=factory)
    return writer, factory


def test_audit_is_persisted_before_api_and_ai_report_is_saved(db, api_writer):
    writer, factory = api_writer
    request = factory.return_value.__enter__.return_value.responses.parse
    response = request.return_value

    def check_before_dispatch(**kwargs):
        snapshots = [call.args[0] for call in db.save_audit.call_args_list]
        assert len(snapshots) == 2
        assert snapshots[0]["leak_check"]["payload_status"] == "prepared_not_sent"
        assert snapshots[1]["leak_check"]["payload_status"] == "dispatch_pending"
        assert snapshots[1]["leak_check"]["api_call_made"] is False
        assert kwargs["input"][1]["content"] == snapshots[1]["sent_payload"]
        db.save_report.assert_not_called()
        return response

    request.side_effect = check_before_dispatch
    process_one(db, writer)
    saved = db.save_report.call_args.kwargs
    assert saved["source"] == "openai"
    assert saved["model"] == "gpt-6-luna"
    assert saved["error"] is None
    assert writer.calls == 1
    final_audit = db.save_audit.call_args.args[0]
    assert final_audit["leak_check"]["payload_status"] == "request_attempted"
    assert final_audit["leak_check"]["api_call_made"] is True
    # Earlier persisted snapshots must not be changed by later state updates.
    assert db.save_audit.call_args_list[0].args[0]["leak_check"]["api_call_made"] is False
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "done")


@pytest.mark.parametrize("failure_at", [1, 2])
def test_pre_dispatch_audit_failure_prevents_client_creation(db, api_writer, failure_at):
    writer, factory = api_writer
    db.save_audit.side_effect = [None] * (failure_at - 1) + [RuntimeError("audit unavailable")]
    process_one(db, writer)
    factory.assert_not_called()
    assert writer.calls == 0
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")


def test_post_dispatch_audit_failure_does_not_claim_success(db, api_writer):
    writer, factory = api_writer
    db.save_audit.side_effect = [None, None, RuntimeError("audit unavailable")]
    process_one(db, writer)
    assert writer.calls == 1
    factory.assert_called_once()
    db.save_report.assert_not_called()
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "failed")


def test_live_privacy_block_uses_template_without_client(db, api_writer):
    writer, factory = api_writer
    db.recent_records.return_value[0]["customer_name"] = "botnet"
    process_one(db, writer)
    factory.assert_not_called()
    assert writer.calls == 0
    assert db.save_report.call_args.kwargs["source"] == "fallback"
    assert db.save_report.call_args.kwargs["error"] == "privacy_check_blocked"


def test_queue_rows_share_session_budget(db, api_writer):
    writer, factory = api_writer
    writer.settings["MAX_AI_CALLS"] = "1"
    first = deepcopy(db.get_incident.return_value)
    second = deepcopy(first)
    second["version"] = 2
    db.claim_report_request.side_effect = [
        {"incident_id": "INC-0007", "version": 1},
        {"incident_id": "INC-0007", "version": 2},
    ]
    db.get_incident.side_effect = [first, second]
    process_one(db, writer)
    process_one(db, writer)
    factory.assert_called_once()
    assert writer.calls == 1
    assert db.save_report.call_args_list[0].kwargs["source"] == "openai"
    assert db.save_report.call_args_list[1].kwargs["error"] == "session_call_limit"
    assert db.save_report.call_args_list[1].kwargs["version"] == 2


def test_api_exception_is_saved_as_template_and_queue_finishes(db, api_writer):
    writer, factory = api_writer
    factory.return_value.__enter__.return_value.responses.parse.side_effect = RuntimeError("private error details")
    process_one(db, writer)
    saved = db.save_report.call_args.kwargs
    assert saved["source"] == "fallback"
    assert saved["error"] == "RuntimeError"
    assert "private error details" not in str(saved)
    assert writer.calls == 1
    db.finish_report_request.assert_called_once_with("INC-0007", 1, "done")
