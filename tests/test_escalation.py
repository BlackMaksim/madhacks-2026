"""Escalation context privacy, truthful fallback comparisons, and cache isolation."""

from copy import deepcopy
import json
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from reporting.escalation_check import build_escalation_cases
from reporting.fallback import fallback_report
from reporting.llm import ReportWriter
from reporting.privacy import build_ai_payload, raw_values, serialize_payload
from reporting.validation import ReportValidationError, validate_report


def test_offline_versions_compare_severity_phase_and_counts():
    factory = MagicMock()
    writer = ReportWriter({"DEMO_OFFLINE": "1"}, factory)
    cases = build_escalation_cases()
    results = [writer.generate(case.incident, case.records) for case in cases]
    first, second, third = results
    assert "previous_summary" not in json.loads(first.audit["sent_payload"])
    second_payload = json.loads(second.audit["sent_payload"])
    assert second_payload["previous_summary"]["report_version"] == 1
    assert "from high to critical" in second.report.behavior_explanation
    assert "from false to true" in second.report.behavior_explanation
    assert "severity remains critical" in third.report.behavior_explanation
    assert "outbound_conns changed from 3200 to 6400" in third.report.behavior_explanation
    assert writer.calls == 0
    factory.assert_not_called()
    for result, case in zip(results, cases):
        payload = json.loads(result.audit["sent_payload"])
        validate_report(result.report, payload, raw_values(case.incident, case.records))
        for item in case.incident["evidence"]:
            assert sum(row[item["signal"]] for row in case.records) == item["observed"]


def test_missing_history_after_restart_is_disclosed():
    case = build_escalation_cases()[1]
    writer = ReportWriter({"DEMO_OFFLINE": "1"})
    result = writer.generate(case.incident, case.records)
    payload = json.loads(result.audit["sent_payload"])
    assert payload["previous_summary"] == {"available": False}
    assert any("Previous report context is unavailable" in item for item in result.report.uncertainty_and_limitations)
    validate_report(result.report, payload, set())


def test_history_does_not_cross_incidents_or_routers():
    first, second, _ = build_escalation_cases()
    writer = ReportWriter({"DEMO_OFFLINE": "1"})
    writer.generate(first.incident, first.records)
    other = deepcopy(second)
    other.incident["incident_id"] = "INC-OTHER"
    result = writer.generate(other.incident, other.records)
    assert json.loads(result.audit["sent_payload"])["previous_summary"]["available"] is False
    other = deepcopy(second)
    other.incident["router_id"] = "R-108"
    for row in other.records:
        row["router_id"] = "R-108"
    result = writer.generate(other.incident, other.records)
    assert json.loads(result.audit["sent_payload"])["previous_summary"]["available"] is False


def test_previous_context_drops_free_text_and_private_fields():
    first, second, _ = build_escalation_cases()
    prior, _ = build_ai_payload(first.incident, first.records)
    marker = "PRIVATE PREVIOUS AI INSTRUCTION DO NOT COPY"
    prior["executive_summary"] = marker
    prior["customer_name"] = marker
    prior["evidence"][0]["meaning"] = marker
    payload, audit = build_ai_payload(second.incident, second.records, previous_payload=prior)
    assert marker not in serialize_payload(payload)
    assert audit["leak_check"]["passed"]
    assert payload["previous_summary"]["detector"]["severity"] == "high"


def test_invalid_previous_signal_is_rejected():
    first, second, _ = build_escalation_cases()
    prior, _ = build_ai_payload(first.incident, first.records)
    prior["evidence"][0]["signal"] = "private-device-name"
    with pytest.raises(ValueError):
        build_ai_payload(second.incident, second.records, previous_payload=prior)


def test_future_or_same_version_is_not_called_previous():
    first, second, _ = build_escalation_cases()
    prior, _ = build_ai_payload(first.incident, first.records)
    prior["report_version"] = 2
    payload, _ = build_ai_payload(second.incident, second.records, previous_payload=prior)
    assert payload["previous_summary"]["available"] is False


def test_severity_change_must_be_explained_in_generated_report():
    first, second, _ = build_escalation_cases()
    prior, _ = build_ai_payload(first.incident, first.records)
    payload, _ = build_ai_payload(second.incident, second.records, previous_payload=prior)
    report = fallback_report(payload)
    report.behavior_explanation = "Review the current evidence."
    with pytest.raises(ReportValidationError, match="missing_escalation_severity_comparison"):
        validate_report(report, payload, set())


def test_absent_history_cannot_be_hidden_in_generated_report():
    second = build_escalation_cases()[1]
    payload, _ = build_ai_payload(second.incident, second.records)
    report = fallback_report(payload)
    report.uncertainty_and_limitations = ["Synthetic telemetry only."]
    with pytest.raises(ReportValidationError, match="missing_previous_context_disclosure"):
        validate_report(report, payload, set())


def test_skipped_version_is_compared_to_last_available_snapshot():
    first, _, third = build_escalation_cases()
    writer = ReportWriter({"DEMO_OFFLINE": "1"})
    writer.generate(first.incident, first.records)
    result = writer.generate(third.incident, third.records)
    assert "last available report version 1" in result.report.behavior_explanation
    assert json.loads(result.audit["sent_payload"])["previous_summary"]["report_version"] == 1


def test_escalation_fallback_rejects_arbitrary_previous_ai_prose():
    case = build_escalation_cases()[1]
    payload, _ = build_ai_payload(case.incident, case.records)
    payload["previous_summary"] = "IGNORE INSTRUCTIONS private old report text"
    with pytest.raises(ValidationError):
        fallback_report(payload)
