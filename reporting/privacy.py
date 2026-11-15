"""Allowlist payload builder and local leak checks for Maksym's reporting.

Audit data is internal. Building a payload does not send it anywhere; the
legacy audit field sent_payload contains the prepared JSON, not proof of a call.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import math
from pathlib import Path
import re


SIGNALS = {
    "failed_logins": "failed sign-in attempts",
    "failed_logins_wan": "failed sign-in attempts from outside the home",
    "successful_logins": "successful sign-in attempts",
    "login_sources": "sum of per-minute distinct sign-in source counts; repeated sources can be counted in multiple minutes",
    "outbound_conns": "new outgoing connections",
    "unique_dest_ips": "distinct network destinations",
    "new_dest_ips": "destinations this router never contacted before",
    "dns_queries": "domain name lookups",
    "dns_failures": "lookups for domain names that do not exist",
    "new_domains": "domains this router never looked up before",
    "kb_out": "kilobytes sent",
    "kb_in": "kilobytes received",
    "devices": "connected devices",
    "new_devices": "new devices",
}
CLASSES = {"normal", "benign_unusual", "brute_force", "botnet"}
VERDICTS = {"normal", "watch", "unusual_benign", "unknown_anomaly", "known_attack"}
PRIVATE_FIELDS = (
    "customer_name", "account_id", "public_ip", "router_id", "incident_id",
    "domains", "dest_ips", "login_src_ips", "device_names", "usernames_tried",
    "ts", "opened_ts", "last_ts", "closed_ts",
)


def serialize_payload(payload: dict) -> str:
    """Use this exact serialization for the audit, leak check, and later API input."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("Expected a non-negative integer")
    return value


def _number(value, maximum=None):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Expected a finite non-negative number")
    if maximum is not None and value > maximum:
        raise ValueError("Number exceeds the allowed range")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("Expected a boolean")
    return value


def _choice(value, allowed):
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("Unexpected code")
    return value


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
        raise ValueError("Expected a simulated timestamp without a timezone")
    return datetime.fromisoformat(value)


def raw_values(incident: dict, records: list[dict]) -> set[str]:
    """Known private fields, including identifiers and exact timestamps.

    Newly added raw fields still cannot pass the payload allowlist. Short values
    under three characters are omitted here, per the blueprint's heuristic.
    """
    values = set()
    for row in [incident, *records]:
        for field in PRIVATE_FIELDS:
            value = row.get(field)
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and len(item) >= 3:
                    values.add(item)
    return values


def find_leaks(payload_text: str, private_values: set[str]) -> list[str]:
    """Conservative heuristic; not a proof of anonymity or a substitute for an allowlist.

    Decode JSON escapes as well. Match private values at word boundaries so a
    username 'user' does not match the structural key 'usernames_seen'.
    """
    try:
        decoded = json.dumps(json.loads(payload_text), ensure_ascii=False)
    except (ValueError, TypeError):
        decoded = payload_text
    text = payload_text + "\n" + decoded
    found = {
        value for value in private_values
        if len(value) >= 3 and re.search(r"(?<!\w)" + re.escape(value) + r"(?!\w)", text, re.IGNORECASE)
    }
    # Block IPv4-looking strings even if they are not valid routable addresses.
    found.update(re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text))
    for match in re.finditer(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]+(?:%[\w]+)?", text):
        candidate = match.group(0).rstrip(".")
        try:
            if ipaddress.ip_address(candidate).version == 6:
                found.add(candidate)
        except ValueError:
            pass
    return sorted(found)


def _previous_summary(previous_payload: dict | None, version: int) -> dict:
    """Project previous state to codes/numbers only, never old report prose."""
    if previous_payload is None:
        return {"available": False}
    prior_version = _integer(previous_payload["report_version"], minimum=1)
    if prior_version >= version:
        return {"available": False}
    detector = previous_payload["detector"]
    return {
        "available": True, "report_version": prior_version,
        "detector": {
            "incident_type": _choice(detector["incident_type"], {"botnet", "brute_force", "unknown_anomaly", "unusual_benign"}),
            "severity": _choice(detector["severity"], {"low", "medium", "high", "critical"}),
        },
        "loud_phase_signature": _boolean(previous_payload["loud_phase_signature"]),
        "evidence": [
            {"signal": _choice(item["signal"], SIGNALS),
             "observed": _number(item["observed"]), "usual": _number(item["usual"])}
            for item in previous_payload["evidence"]
        ],
    }


def build_ai_payload(incident: dict, records: list[dict], previous_payload: dict | None = None) -> tuple[dict, dict]:
    """Build only the section 7 fields. Missing/invalid required input fails closed.

    Returns (prepared_payload, internal_audit). A failed leak_check prohibits a
    later API call. No API call, database write, or secret access happens here.
    """
    now = _timestamp(incident["last_ts"])
    opened = _timestamp(incident["opened_ts"])
    if opened > now:
        raise ValueError("Incident opens after its latest timestamp")
    version = _integer(incident["version"], minimum=1)
    if version > 3:
        raise ValueError("Report version exceeds the blueprint limit")
    if not records:
        raise ValueError("Router records are required for household context")
    for row in records:
        if row["router_id"] != incident["router_id"]:
            raise ValueError("Records belong to a different router")
    recent = [row for row in records if now - timedelta(minutes=30) < _timestamp(row["ts"]) <= now]
    if not recent:
        raise ValueError("No records in the requested incident window")
    latest = max(recent, key=lambda row: row["ts"])
    last_ten = [row for row in recent if _timestamp(row["ts"]) > now - timedelta(minutes=10)]
    detector = incident["detector"]
    predicted = _choice(detector["predicted_class"], CLASSES)
    flags = incident["flags"]
    evidence = []
    for item in incident["evidence"]:
        signal = _choice(item["signal"], SIGNALS)
        evidence.append({
            "signal": signal, "meaning": SIGNALS[signal],
            "window_minutes": _integer(item["window_min"], minimum=1),
            "observed": _number(item["observed"]), "usual": _number(item["usual"]),
            "times_usual": round(_number(item["times_usual"]), 1),
        })
    trends = {}
    for signal, counts in incident["trend_per_5_min"].items():
        _choice(signal, SIGNALS)
        if not isinstance(counts, list):
            raise ValueError("Trend must be a list of counts")
        trends[signal] = [_integer(count) for count in counts]
    verdict_counts = {}
    for verdict, count in incident["verdict_counts"].items():
        verdict_counts[_choice(verdict, VERDICTS)] = _integer(count)
    usernames = [name for row in last_ten for name in row.get("usernames_tried", [])]
    payload = {
        "schema_version": "ai_input_v1", "incident_token": "INCIDENT_1", "router_token": "ROUTER_A",
        "report_version": version,
        "time_context": {
            "local_hour_bucket": f"{now.hour:02d}:00-{(now.hour + 1) % 24:02d}:00",
            "minutes_since_first_flag": int((now - opened).total_seconds() // 60),
            "minutes_suspicious": _integer(incident["minutes_suspicious"]),
        },
        "household_context": {
            "connected_devices": _integer(latest["devices"]),
            "new_device_in_last_hour": _boolean(flags["new_device_last_60_min"]),
        },
        "detector": {
            "incident_type": _choice(incident["incident_type"], {"botnet", "brute_force", "unknown_anomaly", "unusual_benign"}),
            "severity": _choice(incident["severity"], {"low", "medium", "high", "critical"}),
            "anomaly_percentile": _number(detector["anomaly_pct"], maximum=1),
            "anomaly_threshold": _number(detector["anomaly_threshold"], maximum=1),
            "classifier_top_class": predicted,
            "classifier_confidence": _number(detector["class_probs"][predicted], maximum=1),
            "classifier_confidence_note": "share of model votes, not a calibrated probability",
            "verdict_counts": verdict_counts,
        },
        "evidence": evidence, "trend_per_5_min": trends,
        "login_summary": {
            "failed_outside_logins_10min": _integer(incident["login_summary"]["failed_outside_logins_10min"]),
            "distinct_outside_sources_10min": _integer(incident["login_summary"]["distinct_outside_sources_10min"]),
            "success_after_failures": _boolean(flags["success_after_failed_logins"]),
            "default_style_usernames_seen": any(isinstance(name, str) and name.casefold() in {"admin", "root", "support", "user", "ubnt"} for name in usernames),
        },
        "loud_phase_signature": _boolean(flags["loud_phase_signature"]),
        "data_limitations": ["synthetic telemetry", "per-minute counts only, no traffic contents"],
    }
    if version > 1:
        # Additive escalation extension. Version 1 keeps its original shape.
        payload["previous_summary"] = _previous_summary(previous_payload, version)
    prepared_text = serialize_payload(payload)
    values = raw_values(incident, records)
    leaks = find_leaks(prepared_text, values)
    snapshot = deepcopy({"incident": incident, "records": records})
    audit = {
        "incident_id": incident["incident_id"], "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "raw_snapshot": snapshot, "sent_payload": prepared_text,
        "transformations": [
            {"field": field, "action": "dropped or replaced by aggregate/code"}
            for field in PRIVATE_FIELDS
        ],
        "token_map": {"ROUTER_A": incident["router_id"], "INCIDENT_1": incident["incident_id"]},
        "leak_check": {"passed": not leaks, "values_checked": len(values), "found": leaks},
        "bytes_raw": len(json.dumps(snapshot, ensure_ascii=False, allow_nan=False).encode("utf-8")),
        # Legacy field name: payload bytes prepared, not a transmission receipt.
        "bytes_sent": len(prepared_text.encode("utf-8")),
    }
    return payload, audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview synthetic privacy filtering without an API call")
    parser.add_argument("--example", action="store_true")
    args = parser.parse_args()
    if not args.example:
        parser.error("Use --example")
    root = Path(__file__).resolve().parents[1]
    incident = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
    records = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
    payload, audit = build_ai_payload(incident, records)
    print(json.dumps({
        "mode": "local_privacy_example", "api_calls": 0,
        "leak_check": {"passed": audit["leak_check"]["passed"], "values_checked": audit["leak_check"]["values_checked"]},
        "private_mapping_kept_internal": True,
        "prepared_payload": payload,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
