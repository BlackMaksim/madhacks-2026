"""Privacy boundary tests on synthetic data. No network or database required."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from reporting.fallback import fallback_report
from reporting.privacy import build_ai_payload, find_leaks, raw_values, serialize_payload


@pytest.fixture
def inputs():
    root = Path(__file__).resolve().parents[1]
    incident = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
    records = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
    return incident, records


def test_payload_has_contract_shape_and_correct_mapping(inputs):
    incident, records = inputs
    payload, audit = build_ai_payload(incident, records)
    root = Path(__file__).resolve().parents[1]
    example = json.loads((root / "contracts/examples/ai_input.json").read_text(encoding="utf-8"))
    assert payload.keys() == example.keys()
    for section in ("detector", "time_context", "household_context", "login_summary"):
        assert payload[section].keys() == example[section].keys()
    assert payload["time_context"]["local_hour_bucket"] == "19:00-20:00"
    assert payload["time_context"]["minutes_since_first_flag"] == 5
    assert payload["detector"]["classifier_confidence"] == 0.81
    assert payload["evidence"][0]["observed"] == 41
    assert payload["evidence"][0]["window_minutes"] == 10
    assert audit["sent_payload"] == serialize_payload(payload)
    assert audit["leak_check"]["passed"]
    assert fallback_report(payload).severity == incident["severity"]


def test_private_values_and_injection_stay_in_audit_only(inputs):
    incident, records = inputs
    original = deepcopy(inputs)
    payload, audit = build_ai_payload(incident, records)
    text = serialize_payload(payload)
    assert find_leaks(text, raw_values(incident, records)) == []
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in text
    assert "Jordan Miller" not in text
    assert "R-107" not in text
    assert "2026-11-14" not in text
    assert audit["raw_snapshot"]["records"][0]["customer_name"] == "Jordan Miller"
    assert audit["token_map"]["ROUTER_A"] == "R-107"
    assert inputs == original
    audit["raw_snapshot"]["records"][0]["customer_name"] = "changed"
    assert records[0]["customer_name"] == "Jordan Miller"


def test_new_fields_and_free_text_cannot_enter_payload(inputs):
    incident, records = inputs
    marker = "PRIVATE NEW FIELD DO NOT COPY"
    incident["new_field"] = marker
    incident["evidence"][0]["meaning"] = marker
    records[0]["new_private_field"] = marker
    payload, _ = build_ai_payload(incident, records)
    assert marker not in serialize_payload(payload)


@pytest.mark.parametrize("value", ["Jordan Miller", "ACCT-55102", "R-107", "qx7rk2lmz9ta.example"])
def test_inserted_private_values_are_detected(inputs, value):
    incident, records = inputs
    text = json.dumps({"accidental_field": value.swapcase()})
    assert value in find_leaks(text, raw_values(incident, records))


@pytest.mark.parametrize("address", ["203.0.113.5", "999.1.2.3", "2001:db8::1", "::1", "fe80::1234"])
def test_address_shapes_are_blocked_even_without_raw_match(address):
    assert find_leaks(json.dumps({"x": address}), set())


def test_unicode_json_escapes_are_checked():
    value = "Ірина Коваль"
    assert find_leaks(json.dumps({"x": value}, ensure_ascii=True), {value}) == [value]


def test_default_username_becomes_boolean_not_raw_text(inputs):
    incident, records = inputs
    records[0]["usernames_tried"] = ["admin", "user", "root"]
    payload, audit = build_ai_payload(incident, records)
    assert payload["login_summary"]["default_style_usernames_seen"] is True
    assert audit["leak_check"]["passed"]


@pytest.mark.parametrize("value", ["private-name", True, -1, float("nan"), float("inf")])
def test_invalid_evidence_numbers_fail_closed(inputs, value):
    incident, records = inputs
    incident["evidence"][0]["observed"] = value
    with pytest.raises(ValueError):
        build_ai_payload(incident, records)


def test_unknown_signal_fails_closed(inputs):
    incident, records = inputs
    incident["evidence"][0]["signal"] = "private-device-name"
    with pytest.raises(ValueError):
        build_ai_payload(incident, records)


def test_other_router_records_are_rejected(inputs):
    incident, records = inputs
    records[0]["router_id"] = "R-108"
    with pytest.raises(ValueError):
        build_ai_payload(incident, records)


def test_future_records_are_not_used_for_household_context(inputs):
    incident, records = inputs
    future = deepcopy(records[0])
    future.update(ts="2026-11-14T19:48:00", devices=999)
    records.append(future)
    payload, _ = build_ai_payload(incident, records)
    assert payload["household_context"]["connected_devices"] == 11


def test_no_recent_records_is_not_silently_filled_with_zeros(inputs):
    incident, records = inputs
    with pytest.raises(ValueError):
        build_ai_payload(incident, [])


def test_audit_flags_a_private_value_collision(inputs):
    incident, records = inputs
    # A private value colliding with allowed prose is conservatively blocked.
    records[0]["customer_name"] = "domain name lookups"
    incident["evidence"][0]["signal"] = "dns_queries"
    _, audit = build_ai_payload(incident, records)
    assert audit["leak_check"]["passed"] is False
    assert "domain name lookups" in audit["leak_check"]["found"]
