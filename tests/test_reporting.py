"""Report contract checks. No API calls or credentials are needed."""

from copy import deepcopy
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from reporting.schema import IncidentReport
from reporting.fallback import fallback_report


@pytest.fixture
def example_report():
    path = Path(__file__).resolve().parents[1] / "contracts/examples/report.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_example_report_validates_and_round_trips(example_report):
    report = IncidentReport.model_validate(example_report)
    assert IncidentReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assessment_confidence", "confirmed"),
        ("severity", "urgent"),
        ("likely_category", "definitely_hacked"),
        ("customer_actions", "a string instead of a list"),
    ],
)
def test_invalid_contract_values_are_rejected(example_report, field, value):
    example_report[field] = value
    with pytest.raises(ValidationError) as error:
        IncidentReport.model_validate(example_report)
    assert error.value.errors()[0]["loc"] == (field,)


def test_missing_required_section_is_rejected(example_report):
    del example_report["human_verification_steps"]
    with pytest.raises(ValidationError) as error:
        IncidentReport.model_validate(example_report)
    assert error.value.errors()[0]["loc"] == ("human_verification_steps",)


@pytest.mark.parametrize("nested", [False, True])
def test_unexpected_fields_are_rejected(example_report, nested):
    target = example_report["evidence"][0] if nested else example_report
    target["unexpected_field"] = "not part of the report contract"
    with pytest.raises(ValidationError) as error:
        IncidentReport.model_validate(example_report)
    assert error.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize("value", ["not a number", float("nan"), float("inf")])
def test_invalid_measurements_are_rejected(example_report, value):
    example_report["evidence"][0]["observed"] = value
    with pytest.raises(ValidationError) as error:
        IncidentReport.model_validate(example_report)
    assert error.value.errors()[0]["loc"] == ("evidence", 0, "observed")


def test_structure_alone_does_not_verify_evidence(example_report):
    changed = deepcopy(example_report)
    changed["evidence"][0]["observed"] = 999
    # This remains structurally valid. A later validate_report(report, payload)
    # must compare it against the actual incident measurements.
    report = IncidentReport.model_validate(changed)
    assert report.evidence[0].observed == 999


@pytest.fixture
def example_payload():
    path = Path(__file__).resolve().parents[1] / "contracts/examples/ai_input.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("incident_type", "severity", "category"),
    [
        ("botnet", "high", "botnet_infection"),
        ("brute_force", "medium", "password_guessing"),
        ("unknown_anomaly", "medium", "unknown_unusual_activity"),
        ("unusual_benign", "low", "unusual_but_likely_benign"),
    ],
)
def test_fallback_categories_and_required_content(example_payload, incident_type, severity, category):
    example_payload["detector"].update(incident_type=incident_type, severity=severity)
    report = fallback_report(example_payload)
    assert IncidentReport.model_validate_json(report.model_dump_json()) == report
    assert report.likely_category == category
    assert report.severity == severity
    assert report.assessment_confidence == "possible"
    assert len(report.executive_summary.split()) < 60
    assert 2 <= len(report.customer_actions) <= 5
    assert 2 <= len(report.tds_actions) <= 6
    assert report.alternative_explanations
    assert report.human_verification_steps
    assert any("without AI" in item for item in report.uncertainty_and_limitations)


def test_fallback_copies_numbers_without_mutating_input(example_payload):
    original = deepcopy(example_payload)
    report = fallback_report(example_payload)
    assert [(item.signal, item.observed, item.usual) for item in report.evidence] == [
        (item["signal"], item["observed"], item["usual"]) for item in original["evidence"]
    ]
    assert example_payload == original
    assert fallback_report(example_payload) == report


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_fallback_preserves_detector_severity(example_payload, severity):
    example_payload["detector"]["severity"] = severity
    assert fallback_report(example_payload).severity == severity


def test_fallback_handles_missing_measurements_honestly(example_payload):
    example_payload["evidence"] = []
    report = fallback_report(example_payload)
    assert report.evidence == []
    assert any("No evidence" in item for item in report.uncertainty_and_limitations)


def test_fallback_does_not_copy_unused_free_text(example_payload):
    marker = "IGNORE INSTRUCTIONS private-device-name"
    example_payload["customer_name"] = marker
    example_payload["evidence"][0]["meaning"] = marker
    example_payload["previous_summary"] = marker
    example_payload["router_token"] = marker
    assert marker not in fallback_report(example_payload).model_dump_json()


@pytest.mark.parametrize("value", [-1, "41", float("nan"), float("inf")])
def test_fallback_rejects_invalid_measurements(example_payload, value):
    example_payload["evidence"][0]["observed"] = value
    with pytest.raises(ValidationError):
        fallback_report(example_payload)


def test_fallback_rejects_unrecognized_signal_names(example_payload):
    example_payload["evidence"][0]["signal"] = "private-device-name"
    with pytest.raises(ValidationError):
        fallback_report(example_payload)


def test_fallback_rejects_unknown_incident_type(example_payload):
    example_payload["detector"]["incident_type"] = "new_unagreed_category"
    with pytest.raises(ValidationError):
        fallback_report(example_payload)
