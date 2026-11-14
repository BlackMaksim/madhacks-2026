"""Report contract checks. No API calls or credentials are needed."""

from copy import deepcopy
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from reporting.schema import IncidentReport


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
