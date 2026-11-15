"""Regression checks for version matching and the local shareable JSON."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import db
from app.report_export import ExportUnavailable, live_report_download, rehearsal_report_download
from reporting.fallback import fallback_report
from reporting.privacy import build_ai_payload
from reporting.replay import SCENARIOS, load_saved_report


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def evidence():
    incident = json.loads((ROOT / "contracts/examples/incident.json").read_text(encoding="utf-8"))
    records = json.loads((ROOT / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
    payload, audit = build_ai_payload(incident, records)
    row = {
        "incident_id": incident["incident_id"],
        "version": incident["version"],
        "source": "fallback",
        "model": None,
        "created_at": "2026-11-14T19:48:22+00:00",
        "latency_ms": 42,
        "report": fallback_report(payload).model_dump(),
    }
    return incident, row, audit, payload


def test_newer_audit_waits_for_its_own_report(tmp_path, monkeypatch, evidence):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "reports.db")
    db.init_db()
    incident, row, audit, _ = evidence
    incident_id = incident["incident_id"]
    router_id = incident["router_id"]
    db.upsert_incident(incident)
    db.upsert_status([{"router_id": router_id, "status": "critical", "open_incident_id": incident_id}])
    assert db.latest_status()[0]["incident_severity"] == "high"
    db.save_audit(audit)
    db.save_report(incident_id, 1, row["source"], row["model"], 42, None, row["report"])

    escalation = {**incident, "version": 2, "severity": "critical"}
    db.upsert_incident(escalation)
    db.request_report(incident_id, 2)
    db.save_audit({**audit, "version": 2})
    pending = db.investigation_view(router_id)
    assert pending.incident["version"] == 2
    assert pending.report["version"] == pending.audit["version"] == 1
    assert pending.queue_status == "pending"
    assert db.claim_report_request() == {"incident_id": incident_id, "version": 2}
    processing = db.investigation_view(router_id)
    assert processing.queue_status == "in_progress"
    assert processing.report["version"] == processing.audit["version"] == 1

    db.save_report(incident_id, 2, "openai", "gpt-6-luna", 318, None, row["report"])
    db.finish_report_request(incident_id, 2, "done")
    complete = db.investigation_view(router_id)
    assert complete.queue_status == "done"
    assert complete.report["version"] == complete.audit["version"] == 2
    assert complete.report["latency_ms"] == 318

    db.upsert_incident({**escalation, "version": 3})
    db.save_report(incident_id, 3, "fallback", None, 1, None, row["report"])
    missing = db.investigation_view(router_id)
    assert missing.report["version"] == 3
    assert missing.audit is None


@pytest.mark.parametrize("source,model", [("openai", "gpt-6-luna"), ("fallback", None)])
def test_live_export_includes_only_shareable_fields(evidence, source, model):
    _, row, audit, payload = evidence
    with patch("socket.create_connection", side_effect=AssertionError("network call")) as network:
        result = live_report_download(
            {**row, "source": source, "model": model, "error": "INTERNAL_ERROR"},
            {**audit, "environment": {"OPENAI_API_KEY": "a-test-environment-value"}},
        )
        network.assert_not_called()
    exported = json.loads(result)
    assert set(exported) == {"metadata", "report", "prepared_payload"}
    assert exported["prepared_payload"] == payload
    assert exported["report"] == row["report"]
    assert exported["metadata"] == {
        "context": "live_incident", "source": source, "model": model,
        "report_version": 1, "created_at": row["created_at"], "latency_ms": 42,
        "human_review": "pending",
    }
    for private_text in (
        "raw_snapshot", "token_map", "customer_name", "router_id", "OPENAI_API_KEY",
        "a-test-environment-value", "INTERNAL_ERROR", "Jordan Miller", "R-107", "INC-0007",
    ):
        assert private_text not in result


def test_live_export_refuses_mismatch_missing_and_blocked_audits(evidence):
    _, row, audit, payload = evidence
    for changed in (
        None,
        {**audit, "version": 2},
        {**audit, "incident_id": "INC-9999"},
        {**audit, "leak_check": ["unexpected value"]},
        {**audit, "leak_check": {"passed": True, "blocked": True}},
        {**audit, "raw_snapshot": {**audit["raw_snapshot"], "records": []}},
        {**audit, "sent_payload": {**payload, "report_version": 2}},
        {**audit, "sent_payload": {**payload, "household_context": {"custom_env": "example"}}},
    ):
        with pytest.raises(ExportUnavailable):
            live_report_download(row, changed)


@pytest.mark.parametrize("private_text", ["Jordan Miller", "R-117", "sk-fake-credential-for-test-only"])
def test_live_export_rechecks_report_prose(evidence, private_text):
    _, row, audit, _ = evidence
    report = {**row["report"], "executive_summary": f"Internal details {private_text}"}
    with pytest.raises(ExportUnavailable, match="privacy check blocked"):
        live_report_download({**row, "report": report}, audit)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_saved_rehearsal_export_preserves_displayed_wording_and_provenance(scenario):
    saved = load_saved_report(scenario).display_data()
    enriched = {**deepcopy(saved), "token_map": {"ROUTER_A": "R-770"}}
    with patch("socket.create_connection", side_effect=AssertionError("network call")) as network:
        text = rehearsal_report_download(enriched)
        network.assert_not_called()
    exported = json.loads(text)
    assert exported["metadata"] == {
        "source": "saved_rehearsal", "original_source": "openai", "model": saved["model"],
        "report_version": saved["payload"]["report_version"],
        "created_at": None, "latency_ms": None, "human_review": "pending",
        "display_wording_edited": saved["display_wording_edited"],
    }
    assert exported["report"] == saved["report"]
    assert exported["prepared_payload"] == saved["payload"]
    assert "original_report" not in text
    assert "R-770" not in text
