"""Local template reports for Maksym's reporting component (blueprint section 7).

Input is an already-redacted AI payload, not raw router telemetry. This module
does not replace the privacy filter or the payload/report business validator.
"""

import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from reporting.schema import AlternativeExplanation, EvidenceItem, IncidentReport


class _Detector(BaseModel):
    incident_type: Literal["botnet", "brute_force", "unknown_anomaly", "unusual_benign"]
    severity: Literal["low", "medium", "high", "critical"]


class _Measurement(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    signal: Literal[
        "failed_logins", "failed_logins_wan", "successful_logins", "login_sources",
        "outbound_conns", "unique_dest_ips", "new_dest_ips", "dns_queries",
        "dns_failures", "new_domains", "kb_out", "kb_in", "devices", "new_devices",
    ]
    observed: float = Field(ge=0, strict=True)
    usual: float = Field(ge=0, strict=True)


class _FallbackInput(BaseModel):
    """Validate only the projection used here; full payload validation comes later.

    Other payload fields are ignored rather than copied into report prose.
    """

    detector: _Detector
    evidence: list[_Measurement]
    report_version: int = Field(default=1, ge=1, le=3, strict=True)
    previous_summary: "_PreviousSummary | None" = None


class _PreviousSummary(BaseModel):
    available: bool = Field(strict=True)
    report_version: int | None = Field(default=None, ge=1, le=3, strict=True)
    detector: _Detector | None = None
    loud_phase_signature: bool | None = Field(default=None, strict=True)
    evidence: list[_Measurement] = Field(default_factory=list)


_FallbackInput.model_rebuild()


# Fixed prose avoids inserting arbitrary telemetry text into a template report.
_TEMPLATES = {
    "botnet": {
        "category": "botnet_infection",
        "summary": "ROUTER_A has a possible botnet pattern according to the detector. Review the supplied measurements and verify the cause before taking action.",
        "explanation": "The detector identified a pattern associated with botnet activity. Aggregated measurements alone cannot establish an infection or its phase.",
        "alternative": "A software update, device setup, or configuration problem could change network activity.",
        "customer_actions": (
            "Check whether anyone recently installed software or configured a connected device.",
            "Contact TDS support for help checking router settings and available firmware updates.",
        ),
        "tds_action": "Review firmware, configuration changes, and related activity in internal management records.",
        "customer_message": "We noticed unusual activity involving your home router. Please let us know about any recent device or software changes. Our support team can help check the settings.",
    },
    "brute_force": {
        "category": "password_guessing",
        "summary": "ROUTER_A has a possible password-guessing pattern according to the detector. The alert does not establish that anyone gained access.",
        "explanation": "The detector identified a pattern associated with password guessing. Failed attempts do not by themselves establish a successful login or compromise.",
        "alternative": "A household member may have forgotten a password, or an application may be retrying saved credentials.",
        "customer_actions": (
            "Check whether anyone in the household recently had trouble signing in to router settings.",
            "Ask TDS support how to set a strong, unique router administrator password.",
        ),
        "tds_action": "Review login origin and authentication outcomes in internal router logs.",
        "customer_message": "We noticed an unusual sign-in pattern involving your router. Please let us know whether you recently had trouble signing in. Our support team can help review your password settings.",
    },
    "unknown_anomaly": {
        "category": "unknown_unusual_activity",
        "summary": "ROUTER_A shows unusual activity that the detector has not assigned to a known pattern. The cause remains uncertain and needs human review.",
        "explanation": "The detector reported an unknown anomaly. This does not identify an attack type, and unusual behavior can have harmless causes.",
        "alternative": "A change in household usage or a scheduled software update may explain the activity.",
        "customer_actions": (
            "Check whether household internet use or connected devices changed recently.",
            "Contact TDS support if you notice service problems or need help reviewing the activity.",
        ),
        "tds_action": "Compare the supplied evidence with internal history and check for recent usage or configuration changes.",
        "customer_message": "We noticed a change in your router's activity. It may have a harmless explanation. Please let our support team know about recent changes or service problems.",
    },
    "unusual_benign": {
        "category": "unusual_but_likely_benign",
        "summary": "ROUTER_A shows an unusual pattern that the detector considers probably harmless. Check recent changes if needed; this advisory does not establish an attack.",
        "explanation": "The detector assigned the unusual-but-likely-benign category. A harmless cause is plausible, but the category is not a guarantee of safety.",
        "alternative": "Ordinary variation in household usage may explain the change without a new device or application.",
        "customer_actions": (
            "Check whether the activity matches recent device setup or normal household use.",
            "Contact TDS support if the activity is unexpected or your service is affected.",
        ),
        "tds_action": "Check whether internal records and customer feedback support a harmless usage change.",
        "customer_message": "We noticed a change in your router's activity that may be part of normal use. Please check whether it matches a recent change at home. Contact our support team if you notice any problems.",
    },
}


def fallback_report(payload: dict) -> IncidentReport:
    """Build a deterministic report without network calls or reading secrets.

    Invalid required values raise ValidationError; they are not guessed. The
    future reporter must handle invalid inputs separately from API failures.
    """

    input_fields = dict(payload)
    if payload.get("report_version", 1) == 1:
        # Version 1 has no prior context. Preserve the original behavior of
        # ignoring an unused arbitrary-text previous_summary field entirely.
        input_fields.pop("previous_summary", None)
    data = _FallbackInput.model_validate(input_fields)
    template = _TEMPLATES[data.detector.incident_type]
    evidence = [
        EvidenceItem(
            signal=item.signal,
            observed=item.observed,
            usual=item.usual,
            interpretation=(
                "This is the sum of per-minute distinct-source counts, not unique sources across the whole window. Compare it with the usual summed baseline."
                if item.signal == "login_sources" else
                "This is a supplied measurement and its usual baseline. Their difference alone does not establish the cause."
            ),
        )
        for item in data.evidence
    ]
    limitations = [
        "Generated without AI using a local template.",
        "This prototype uses synthetic telemetry, not validated real-world incident data.",
        "Aggregated counts do not reveal traffic contents or establish a compromise.",
        "Classifier confidence is not a calibrated probability.",
    ]
    if not evidence:
        limitations.append("No evidence measurements were supplied; this report only restates the detector category.")
    behavior = template["explanation"]
    if data.report_version > 1:
        previous = data.previous_summary
        if (previous is None or not previous.available or previous.detector is None
                or previous.report_version is None or previous.report_version >= data.report_version):
            limitations.append("Previous report context is unavailable; changes from an earlier report cannot be assessed.")
        else:
            behavior += (
                f" Compared with the last available report version {previous.report_version},"
                f" severity changed from {previous.detector.severity} to {data.detector.severity}."
                if previous.detector.severity != data.detector.severity else
                f" Compared with the last available report version {previous.report_version}, severity remains {data.detector.severity}."
            )
            if previous.detector.incident_type != data.detector.incident_type:
                behavior += f" The detector category changed from {previous.detector.incident_type} to {data.detector.incident_type}."
            # Both flags are validated booleans; arbitrary text is not inserted.
            current_loud = payload.get("loud_phase_signature")
            if type(current_loud) is bool and previous.loud_phase_signature is not None:
                if current_loud != previous.loud_phase_signature:
                    behavior += f" The loud-phase flag changed from {str(previous.loud_phase_signature).lower()} to {str(current_loud).lower()}."
            prior_evidence = {item.signal: item for item in previous.evidence}
            for item in data.evidence:
                prior = prior_evidence.get(item.signal)
                if prior is not None and prior.observed != item.observed:
                    behavior += f" {item.signal} changed from {prior.observed:g} to {item.observed:g}."

    return IncidentReport(
        executive_summary=template["summary"],
        severity=data.detector.severity,
        severity_rationale="Severity is copied from the detector, not independently assessed by this template.",
        likely_category=template["category"],
        assessment_confidence="possible",
        evidence=evidence,
        behavior_explanation=behavior,
        alternative_explanations=[AlternativeExplanation(
            explanation=template["alternative"],
            why_less_likely="The template cannot rank this explanation against others from the supplied counts alone; it requires human review.",
            what_would_confirm_it="Ask the customer about recent changes and compare their account with internal management records.",
        )],
        customer_actions=list(template["customer_actions"]),
        tds_actions=[
            template["tds_action"],
            "Have a human analyst verify the cause before considering any router isolation.",
        ],
        uncertainty_and_limitations=limitations,
        human_verification_steps=[
            "Review the supplied measurements against internal records and ask the customer about relevant changes.",
        ],
        customer_message=template["customer_message"],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview a local template report. No API calls.")
    parser.add_argument("--example", action="store_true", help="Use the synthetic example payload")
    args = parser.parse_args()
    if not args.example:
        parser.error("Use --example to preview the synthetic report")
    example = Path(__file__).resolve().parents[1] / "contracts/examples/ai_input.json"
    payload = json.loads(example.read_text(encoding="utf-8"))
    print(fallback_report(payload).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
