"""Reporter-level injection proof without credentials, API, or SQLite."""

import json

import pytest

from reporting import llm
from reporting.injection_check import INJECTION_DEVICE, _synthetic_r104, run_injection_check
from reporting.privacy import build_ai_payload


def test_local_rehearsal_passes_and_never_creates_a_client():
    result = run_injection_check()
    assert result["checks_passed"]
    assert result["router_id"] == "R-104"
    assert result["api_client_creations"] == 0
    assert result["api_requests_attempted"] == 0
    assert result["deliberate_leak_blocked"]
    assert result["both_queue_requests_done"]


def test_deliberate_fault_patch_does_not_survive_rehearsal():
    original = llm.build_ai_payload
    run_injection_check()
    assert llm.build_ai_payload is original
    db = _synthetic_r104()
    payload, audit = llm.build_ai_payload(db.incident, db.records)
    assert "deliberate_leak" not in payload
    assert audit["leak_check"]["passed"]


@pytest.mark.parametrize("field", ["device_names", "usernames_tried"])
def test_attacker_controlled_text_is_kept_internal(field):
    db = _synthetic_r104()
    db.records[0][field] = [INJECTION_DEVICE]
    payload, audit = build_ai_payload(db.incident, db.records)
    assert INJECTION_DEVICE not in json.dumps(payload)
    assert INJECTION_DEVICE in json.dumps(audit["raw_snapshot"])
    assert audit["leak_check"]["passed"]


def test_cli_summary_does_not_echo_internal_customer_identity():
    result = run_injection_check()
    text = json.dumps(result)
    assert "Jordan Miller" not in text
    assert "ACCT-55102" not in text
    assert "198.51.100.23" not in text
