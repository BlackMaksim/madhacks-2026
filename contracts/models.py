"""Pydantic models for data passed between EdgeSentinel components."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


# These values must match detection/config.py.
ClassName = Literal["normal", "benign_unusual", "brute_force", "botnet"]

Verdict = Literal[
    "normal",
    "watch",
    "unusual_benign",
    "unknown_anomaly",
    "known_attack",
]

IncidentType = Literal[
    "unusual_benign",
    "unknown_anomaly",
    "brute_force",
    "botnet",
]

Severity = Literal["low", "medium", "high", "critical"]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
Count = Annotated[int, Field(ge=0)]


class ContractModel(BaseModel):
    """Base class: reject fields that are not in the agreed contract."""

    model_config = ConfigDict(extra="forbid")


class Record(ContractModel):
    """One simulated minute of router telemetry, including internal fields."""

    router_id: str
    ts: str
    customer_name: str
    account_id: str
    public_ip: str
    failed_logins: Count
    failed_logins_wan: Count
    successful_logins: Count
    login_sources: Count
    outbound_conns: Count
    unique_dest_ips: Count
    new_dest_ips: Count
    dns_queries: Count
    dns_failures: Count
    new_domains: Count
    kb_out: Count
    kb_in: Count
    devices: Count
    new_devices: Count
    login_src_ips: list[str]
    usernames_tried: list[str]
    dest_ips: list[str]
    domains: list[str]
    device_names: list[str]


class ScoreRow(ContractModel):
    """One detector score for one router during one simulated minute."""

    router_id: str
    ts: str
    anomaly_score: float
    anomaly_pct: Probability
    flagged: bool

    p_normal: Probability
    p_benign_unusual: Probability
    p_brute_force: Probability
    p_botnet: Probability

    predicted_class: ClassName
    class_conf: Probability
    verdict: Verdict


class EvidenceItem(ContractModel):
    """One signal that helps explain why an incident was opened."""

    signal: str
    window_min: int = Field(ge=1)
    observed: float
    usual: float
    times_usual: float


class IncidentDetector(ContractModel):
    """Detector output attached to an incident."""

    anomaly_pct: Probability
    anomaly_threshold: Probability
    predicted_class: ClassName
    class_probs: dict[ClassName, Probability]
    model_version: str


class IncidentFlags(ContractModel):
    """Boolean conditions recorded by the incident manager."""

    new_device_last_60_min: bool
    success_after_failed_logins: bool
    loud_phase_signature: bool


class LoginSummary(ContractModel):
    """Summarized login activity attached to an incident."""

    failed_outside_logins_10min: int = Field(ge=0)
    distinct_outside_sources_10min: int = Field(ge=0)


class Incident(ContractModel):
    """The shared incident format used by the engine, reporter, and dashboard."""

    incident_id: str
    router_id: str
    status: Literal["open", "resolved"]

    opened_ts: str
    last_ts: str
    closed_ts: str | None

    version: int = Field(ge=1)
    incident_type: IncidentType
    severity: Severity

    verdict_counts: dict[Verdict, int]
    minutes_suspicious: int = Field(ge=0)

    detector: IncidentDetector
    evidence: list[EvidenceItem]
    trend_per_5_min: dict[str, list[int]]
    flags: IncidentFlags
    login_summary: LoginSummary
