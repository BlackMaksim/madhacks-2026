"""Business checks beyond the report JSON schema; no model or network access.

These checks verify selected invariants, not every factual claim in free prose.
Human review and the six-scenario quality pass remain necessary.
"""

import math
import re

from reporting.privacy import find_leaks
from reporting.schema import IncidentReport


CATEGORIES = {
    "botnet": "botnet_infection",
    "brute_force": "password_guessing",
    "unknown_anomaly": "unknown_unusual_activity",
    "unusual_benign": "unusual_but_likely_benign",
}


class ReportValidationError(ValueError):
    """Only fixed non-sensitive reason codes are used as messages."""


def validate_report(report: IncidentReport, payload: dict, private_values: set[str]) -> tuple[IncidentReport, list[str]]:
    """Return a repaired copy and warnings, or reject it for a template fallback."""
    checked = IncidentReport.model_validate(report.model_dump()).model_copy(deep=True)
    warnings = []
    # Scan original output before dropping fields or repairing mismatches.
    if find_leaks(checked.model_dump_json(), private_values):
        raise ReportValidationError("private_value_in_output")
    if re.search(r"\b(?:confirmed|definitely|proven|certainly)\b", checked.model_dump_json(), re.IGNORECASE):
        raise ReportValidationError("unsupported_certainty")
    if not checked.executive_summary.strip() or len(checked.executive_summary.split()) >= 60:
        raise ReportValidationError("summary_length")
    if checked.severity != payload["detector"]["severity"]:
        checked.severity = payload["detector"]["severity"]
        checked.severity_rationale = "Severity copied from the detector; the generated severity differed and was corrected."
        warnings.append("severity_corrected")
    category = CATEGORIES[payload["detector"]["incident_type"]]
    if checked.likely_category != category:
        # Unlike a label-only fix, fallback avoids retaining prose explaining
        # the wrong attack type. No paid retry is used in the budget version.
        raise ReportValidationError("category_mismatch")
    expected = {item["signal"]: item for item in payload["evidence"]}
    valid_evidence = []
    for item in checked.evidence:
        source = expected.get(item.signal)
        if source is not None and all(
            math.isclose(getattr(item, field), source[field], rel_tol=0, abs_tol=1e-6)
            for field in ("observed", "usual")
        ):
            valid_evidence.append(item)
        else:
            warnings.append("unsupported_evidence_dropped")
    if not valid_evidence:
        raise ReportValidationError("no_supported_evidence")
    checked.evidence = valid_evidence
    if not 2 <= len(checked.customer_actions) <= 5 or not 2 <= len(checked.tds_actions) <= 6:
        raise ReportValidationError("action_counts")
    if not checked.alternative_explanations or not checked.human_verification_steps or not checked.uncertainty_and_limitations:
        raise ReportValidationError("missing_report_sections")
    for items in (checked.customer_actions, checked.tds_actions, checked.human_verification_steps, checked.uncertainty_and_limitations):
        if any(not item.strip() for item in items):
            raise ReportValidationError("empty_report_content")
    for alternative in checked.alternative_explanations:
        if any(not value.strip() for value in alternative.model_dump().values()):
            raise ReportValidationError("empty_alternative")
    if any(not value.strip() for value in (checked.severity_rationale, checked.behavior_explanation, checked.customer_message)):
        raise ReportValidationError("empty_report_content")
    sentence_count = len([part for part in re.split(r"[.!?]+(?:\s+|$)", checked.customer_message) if part.strip()])
    if not 2 <= sentence_count <= 4:
        raise ReportValidationError("customer_message_sentences")
    return checked, warnings
