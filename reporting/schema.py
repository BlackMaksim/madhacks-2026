"""Report structure from blueprint section 7, shared by AI and fallback.

This validates structure, not the truth of the report. Matching evidence and
severity to the input, privacy, and prose rules need separate business checks.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ReportModel(BaseModel):
    """Reject unexpected fields throughout the report."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class EvidenceItem(ReportModel):
    """A measurement copied from the input plus its interpretation."""

    signal: str
    observed: float
    usual: float
    interpretation: str


class AlternativeExplanation(ReportModel):
    """An alternative hypothesis and a way for a human to check it."""

    explanation: str
    why_less_likely: str
    what_would_confirm_it: str


class IncidentReport(ReportModel):
    """The same required fields for both AI and template reports."""

    executive_summary: str
    severity: Literal["low", "medium", "high", "critical"]
    severity_rationale: str
    likely_category: Literal[
        "botnet_infection",
        "password_guessing",
        "unusual_but_likely_benign",
        "unknown_unusual_activity",
    ]
    assessment_confidence: Literal["possible", "likely"]
    evidence: list[EvidenceItem]
    behavior_explanation: str
    alternative_explanations: list[AlternativeExplanation]
    customer_actions: list[str]
    tds_actions: list[str]
    uncertainty_and_limitations: list[str]
    human_verification_steps: list[str]
    customer_message: str
