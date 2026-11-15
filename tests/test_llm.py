"""Structured-report validation and bounded API orchestration using mocks only."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reporting.llm import ReportWriter
from reporting.privacy import build_ai_payload, raw_values
from reporting.schema import IncidentReport
from reporting.validation import ReportValidationError, validate_report


@pytest.fixture
def example():
    root = Path(__file__).resolve().parents[1]
    def read(relative):
        return json.loads((root / relative).read_text(encoding="utf-8"))
    incident = read("contracts/examples/incident.json")
    records = read("reporting/examples/privacy_records.json")
    report = IncidentReport.model_validate(read("contracts/examples/report.json"))
    payload, _ = build_ai_payload(incident, records)
    return incident, records, report, payload


@pytest.fixture
def settings():
    return {"OPENAI_API_KEY": "synthetic-test-key-not-real", "OPENAI_MODEL": "gpt-6-luna", "DEMO_OFFLINE": "0", "MAX_AI_CALLS": "20"}


@pytest.fixture
def factory(example):
    mocked = MagicMock()
    mocked.return_value.__enter__.return_value.responses.parse.return_value = SimpleNamespace(
        status="completed", output_parsed=example[2],
        usage=SimpleNamespace(input_tokens=2000, output_tokens=1000),
    )
    return mocked


def test_valid_report_is_checked_without_mutation(example):
    incident, records, report, payload = example
    original = report.model_dump()
    checked, warnings = validate_report(report, payload, raw_values(incident, records))
    assert warnings == []
    assert checked == report
    assert checked is not report
    assert report.model_dump() == original


def test_severity_is_repaired_with_explicit_warning(example):
    _, _, report, payload = example
    report.severity = "low"
    checked, warnings = validate_report(report, payload, set())
    assert checked.severity == "high"
    assert "severity_corrected" in warnings
    assert report.severity == "low"


def test_invented_evidence_is_dropped_if_supported_evidence_remains(example):
    _, _, report, payload = example
    report.evidence[0].observed = 999
    checked, warnings = validate_report(report, payload, set())
    assert [item.signal for item in checked.evidence] == ["new_domains"]
    assert warnings == ["unsupported_evidence_dropped"]


@pytest.mark.parametrize("kind", ["certainty", "category", "all_evidence", "actions", "alternatives", "empty_section", "message"])
def test_bad_report_content_is_rejected(example, kind):
    _, _, report, payload = example
    if kind == "certainty":
        report.executive_summary = "This is definitely a botnet."
    elif kind == "category":
        report.likely_category = "password_guessing"
    elif kind == "all_evidence":
        for item in report.evidence:
            item.observed = 999
    elif kind == "actions":
        report.customer_actions = []
    elif kind == "alternatives":
        report.alternative_explanations = []
    elif kind == "empty_section":
        report.human_verification_steps = [""]
    else:
        report.customer_message = "Only one sentence."
    with pytest.raises(ReportValidationError):
        validate_report(report, payload, set())


def test_private_output_is_rejected_before_repairs(example):
    incident, records, report, payload = example
    report.customer_message = "Please contact Jordan Miller. We can help."
    with pytest.raises(ReportValidationError, match="private_value_in_output"):
        validate_report(report, payload, raw_values(incident, records))


def test_live_request_is_luna_only_bounded_and_contains_no_raw_identity(example, settings, factory):
    incident, records, _, _ = example
    writer = ReportWriter(settings, factory)
    result = writer.generate(incident, records)
    assert result.source == "openai"
    assert result.input_tokens == 2000
    assert writer.calls == 1
    assert result.audit["leak_check"]["payload_status"] == "request_attempted"
    assert factory.call_args.kwargs["max_retries"] == 0
    request = factory.return_value.__enter__.return_value.responses.parse
    request.assert_called_once()
    arguments = request.call_args.kwargs
    assert arguments["model"] == "gpt-6-luna"
    assert arguments["max_output_tokens"] == 2000
    assert arguments["reasoning"] == {"effort": "none"}
    assert arguments["store"] is False
    text = json.dumps(arguments["input"])
    for private in ("Jordan Miller", "R-107", "ACCT-55102", "198.51.100.23", "IGNORE PREVIOUS INSTRUCTIONS"):
        assert private not in text


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("DEMO_OFFLINE", "1", "offline_mode"),
    ("DEMO_OFFLINE", "unexpected", "invalid_settings"),
    ("OPENAI_API_KEY", "", "api_key_missing"),
    ("OPENAI_MODEL", "gpt-6-astra", "budget_model_requires_luna"),
    ("MAX_AI_CALLS", "0", "invalid_settings"),
])
def test_guard_conditions_make_zero_requests(example, settings, factory, field, value, reason):
    settings[field] = value
    writer = ReportWriter(settings, factory)
    result = writer.generate(example[0], example[1])
    assert result.source == "fallback"
    assert result.error == reason
    assert writer.calls == 0
    factory.assert_not_called()


def test_private_payload_collision_blocks_client_creation(example, settings, factory):
    incident, records, _, _ = example
    records[0]["customer_name"] = "botnet"
    writer = ReportWriter(settings, factory)
    result = writer.generate(incident, records)
    assert result.error == "privacy_check_blocked"
    factory.assert_not_called()


def test_session_cap_prevents_second_request(example, settings, factory):
    settings["MAX_AI_CALLS"] = "1"
    writer = ReportWriter(settings, factory)
    writer.generate(example[0], example[1])
    second = writer.generate(example[0], example[1])
    assert second.error == "session_call_limit"
    assert writer.calls == 1
    factory.assert_called_once()


def test_incident_cap_uses_internal_id_and_prevents_fourth_call(example, settings, factory):
    writer = ReportWriter(settings, factory)
    for version in (1, 2, 3):
        incident = deepcopy(example[0])
        incident["version"] = version
        writer.generate(incident, example[1])
    result = writer.generate(example[0], example[1])
    assert result.error == "incident_call_limit"
    assert writer.calls == 3


def test_api_failure_uses_template_without_retry_or_error_message_leak(example, settings, factory):
    request = factory.return_value.__enter__.return_value.responses.parse
    request.side_effect = RuntimeError("sensitive request details")
    writer = ReportWriter(settings, factory)
    result = writer.generate(example[0], example[1])
    assert result.source == "fallback"
    assert result.error == "RuntimeError"
    assert "sensitive request details" not in str(result)
    assert writer.calls == 1
    request.assert_called_once()


def test_validation_failure_uses_template_without_retry(example, settings, factory):
    example[2].executive_summary = "Definitely malicious activity."
    writer = ReportWriter(settings, factory)
    result = writer.generate(example[0], example[1])
    assert result.source == "fallback"
    assert result.error == "unsupported_certainty"
    assert writer.calls == 1


def test_incomplete_response_uses_template(example, settings, factory):
    response = factory.return_value.__enter__.return_value.responses.parse.return_value
    response.status = "incomplete"
    response.output_parsed = None
    result = ReportWriter(settings, factory).generate(example[0], example[1])
    assert result.source == "fallback"
    assert result.error == "no_completed_report"


def test_same_version_is_not_sent_twice_in_one_writer(example, settings, factory):
    writer = ReportWriter(settings, factory)
    writer.generate(example[0], example[1])
    result = writer.generate(example[0], example[1])
    assert result.error == "version_already_attempted"
    assert writer.calls == 1
    factory.assert_called_once()


def test_matching_number_with_wrong_source_count_unit_is_rejected(example):
    _, _, report, payload = example
    payload["evidence"].append({"signal": "login_sources", "observed": 10, "usual": 1})
    item = report.evidence[0].model_copy(update={
        "signal": "login_sources", "observed": 10.0, "usual": 1.0,
        "interpretation": "The observed count of distinct sign-in sources is above usual.",
    })
    report.evidence.append(item)
    with pytest.raises(ReportValidationError, match="login_source_aggregation_ambiguous"):
        validate_report(report, payload, set())
    item.interpretation = "The sum of per-minute source counts is elevated; repeated sources can appear in multiple minutes."
    checked, _ = validate_report(report, payload, set())
    assert checked.evidence[-1].signal == "login_sources"
