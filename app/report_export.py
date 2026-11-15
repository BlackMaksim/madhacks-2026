"""Build a local JSON download from a displayable report and its payload."""

from datetime import datetime
import json
import re

from reporting.privacy import SIGNALS, VERDICTS, find_leaks, raw_values
from reporting.schema import IncidentReport


class ExportUnavailable(ValueError):
    """A safe message to show when the report cannot be shared."""


def _fields(names: str) -> dict:
    return dict.fromkeys(names.split())


# The reporter builds these approved fields. Reject unknown fields instead of
# stripping them so a download always contains the exact prepared payload.
PAYLOAD_SHAPE = {
    **_fields("schema_version incident_token router_token report_version loud_phase_signature"),
    "time_context": _fields("local_hour_bucket minutes_since_first_flag minutes_suspicious"),
    "household_context": _fields("connected_devices new_device_in_last_hour"),
    "detector": {
        **_fields(
            "incident_type severity anomaly_percentile anomaly_threshold "
            "classifier_top_class classifier_confidence classifier_confidence_note"
        ),
        "verdict_counts": dict.fromkeys(VERDICTS),
    },
    "evidence": [_fields("signal meaning window_minutes observed usual times_usual")],
    "trend_per_5_min": dict.fromkeys(SIGNALS, [None]),
    "login_summary": _fields(
        "failed_outside_logins_10min distinct_outside_sources_10min summed_login_sources_10min "
        "success_after_failures default_style_usernames_seen"
    ),
    "data_limitations": [None],
    "previous_summary": {
        **_fields("available report_version loud_phase_signature"),
        "detector": _fields("incident_type severity"),
        "evidence": [_fields("signal observed usual")],
    },
}

_PRIVATE_TEXT = re.compile(
    r"\b(?:R-\d{3,}|INC-\d+|ACCT-[a-z0-9-]+|sk-[a-z0-9_-]{8,}|"
    r"gh[pousr]_[a-z0-9_]{8,}|github_pat_[a-z0-9_]{8,}|"
    r"OPENAI_API_KEY|OPENAI_MODEL|DEMO_OFFLINE|MAX_AI_CALLS|EDGESENTINEL_DB)\b",
    re.IGNORECASE,
)


def _matches_shape(value, shape) -> bool:
    if isinstance(shape, dict):
        return isinstance(value, dict) and all(
            key in shape and _matches_shape(item, shape[key]) for key, item in value.items()
        )
    if isinstance(shape, list):
        return isinstance(value, list) and all(_matches_shape(item, shape[0]) for item in value)
    return type(value) in (bool, int, float, str)


def _serialize_download(report: dict, payload: dict, metadata: dict, private_values: set[str]) -> str:
    version = metadata["report_version"]
    if (
        not _matches_shape(payload, PAYLOAD_SHAPE)
        or payload.get("schema_version") not in ("ai_input_v1", "ai_input_v2")
        or payload.get("incident_token") != "INCIDENT_1"
        or payload.get("router_token") != "ROUTER_A"
        or type(version) is not int
        or not 1 <= version <= 3
        or type(payload.get("report_version")) is not int
        or payload["report_version"] != version
    ):
        raise ExportUnavailable("The prepared payload does not match the displayed report.")

    model = metadata["model"]
    if model is not None and (
        not isinstance(model, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}", model)
    ):
        raise ExportUnavailable("The report model metadata is invalid.")

    try:
        content = {
            "model": model,
            "report": IncidentReport.model_validate(report).model_dump(),
            "prepared_payload": payload,
        }
        text = json.dumps(content, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ExportUnavailable("The report or prepared payload is invalid.") from error
    if _PRIVATE_TEXT.search(text) or find_leaks(text, private_values):
        raise ExportUnavailable("The export privacy check blocked this download.")

    return json.dumps(
        {"metadata": metadata, "report": content["report"], "prepared_payload": payload},
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    )


def live_report_download(row: dict, audit: dict | None) -> str:
    """Export a live AI or template report using only its own passing audit."""
    if (
        audit is None
        or audit.get("incident_id") != row["incident_id"]
        or audit.get("version") != row["version"]
    ):
        raise ExportUnavailable("A matching privacy audit is required to download this report.")

    check = audit.get("leak_check") or {}
    if not isinstance(check, dict) or check.get("passed") is not True or check.get("blocked"):
        raise ExportUnavailable("A passing privacy audit is required to download this report.")

    try:
        snapshot = audit["raw_snapshot"]
        incident, records = snapshot["incident"], snapshot["records"]
        if incident["incident_id"] != row["incident_id"] or incident["version"] != row["version"]:
            raise ValueError("Audit snapshot mismatch")
        if not isinstance(records, list) or not records:
            raise ValueError("Missing audit records")
        private_values = raw_values(incident, records)
        private_values.update(
            value for value in (audit.get("token_map") or {}).values() if isinstance(value, str)
        )
        stored_payload = audit["sent_payload"]
        payload = json.loads(stored_payload) if isinstance(stored_payload, str) else stored_payload
        created_at = datetime.fromisoformat(row["created_at"])
        latency_ms = row["latency_ms"]
        if created_at.tzinfo is None or type(latency_ms) is not int or latency_ms < 0:
            raise ValueError("Invalid generation metadata")
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExportUnavailable("The matching audit or generation metadata is incomplete.") from error

    source = row["source"]
    if source not in ("openai", "fallback"):
        raise ExportUnavailable("The report source is unknown.")
    return _serialize_download(row["report"], payload, {
        "source": source,
        "context": "live_incident",
        "model": row["model"] if source == "openai" else None,
        "report_version": row["version"],
        "created_at": created_at.isoformat(),
        "latency_ms": latency_ms,
        "human_review": "pending",
    }, private_values)


def rehearsal_report_download(saved: dict) -> str:
    """Export the displayed wording and payload from a validated rehearsal fixture."""
    if saved.get("source") != "saved_rehearsal" or saved.get("original_source") != "openai":
        raise ExportUnavailable("The rehearsal provenance is unavailable.")
    payload = saved["payload"]
    return _serialize_download(saved["report"], payload, {
        "source": "saved_rehearsal",
        "original_source": "openai",
        "model": saved["model"],
        "report_version": payload.get("report_version"),
        # The saved fixtures do not record the original generation time or latency.
        "created_at": None,
        "latency_ms": None,
        "human_review": "pending",
        "display_wording_edited": saved.get("display_wording_edited") is True,
    }, set())
