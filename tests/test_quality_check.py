"""Synthetic scenario consistency and quality-pass orchestration, no API calls."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reporting.fallback import fallback_report
from reporting.privacy import build_ai_payload, raw_values
from reporting.quality_cases import build_quality_cases
from reporting.quality_check import run_quality_check
from reporting.validation import CATEGORIES, validate_report


@pytest.mark.parametrize("case", build_quality_cases(), ids=lambda case: case.name)
def test_synthetic_fixture_is_consistent_and_produces_valid_report(case):
    payload, audit = build_ai_payload(case.incident, case.records)
    assert audit["leak_check"]["passed"]
    assert len(case.records) == 10
    for item in case.incident["evidence"]:
        assert sum(row[item["signal"]] for row in case.records) == item["observed"]
    for row in case.records:
        assert row["failed_logins_wan"] <= row["failed_logins"]
        assert row["new_dest_ips"] <= row["unique_dest_ips"] <= row["outbound_conns"]
    report = fallback_report(payload)
    checked, warnings = validate_report(report, payload, raw_values(case.incident, case.records))
    assert not warnings
    assert checked.likely_category == CATEGORIES[case.incident["incident_type"]]


def test_six_distinct_scenarios_cover_flags_and_severities():
    cases = {case.name: case for case in build_quality_cases()}
    assert len(cases) == 6
    assert len({case.incident["incident_id"] for case in cases.values()}) == 6
    assert cases["botnet_loud"].incident["severity"] == "critical"
    assert cases["botnet_loud"].incident["flags"]["loud_phase_signature"] is True
    assert cases["brute_force_fast"].incident["flags"]["success_after_failed_logins"] is False
    assert cases["brute_force_slow_success"].records[-1]["successful_logins"] == 1
    assert cases["new_device"].incident["flags"]["new_device_last_60_min"] is True


def test_default_run_forces_offline_even_when_environment_is_live(tmp_path):
    factory = MagicMock()
    output = tmp_path / "offline"
    summary = run_quality_check({"DEMO_OFFLINE": "0"}, output_dir=output, client_factory=factory)
    factory.assert_not_called()
    assert summary["api_requests_attempted"] == 0
    assert summary["scenarios_processed"] == 6
    assert all(row["source"] == "fallback" and row["automatic_checks_passed"] for row in summary["results"])
    assert all(row["human_review"] == "pending" for row in summary["results"])
    assert len(list(output.glob("*.json"))) == 7
    for file in output.glob("*.json"):
        text = file.read_text(encoding="utf-8")
        assert "Jordan Miller" not in text
        assert "ACCT-55102" not in text
        assert "raw_snapshot" not in text
        assert "token_map" not in text


def test_live_pass_is_six_requests_max_without_exposing_credentials():
    factory = MagicMock()
    request = factory.return_value.__enter__.return_value.responses.parse

    def synthetic_response(**kwargs):
        payload = json.loads(kwargs["input"][1]["content"])
        # Mock transport only: actual quality of model prose still needs human review.
        return SimpleNamespace(status="completed", output_parsed=fallback_report(payload), usage=None)

    request.side_effect = synthetic_response
    summary = run_quality_check({"OPENAI_API_KEY": "synthetic-test-key", "OPENAI_MODEL": "gpt-6-luna"}, send=True, client_factory=factory)
    assert summary["api_requests_attempted"] == 6
    assert request.call_count == 6
    assert summary["scenarios_processed"] == 6
    assert "synthetic-test-key" not in str(summary)


def test_live_pass_stops_at_first_api_failure():
    factory = MagicMock()
    request = factory.return_value.__enter__.return_value.responses.parse
    request.side_effect = RuntimeError("private details")
    summary = run_quality_check({"OPENAI_API_KEY": "synthetic-test-key", "OPENAI_MODEL": "gpt-6-luna"}, send=True, client_factory=factory)
    assert summary["api_requests_attempted"] == 1
    assert summary["scenarios_processed"] == 1
    assert summary["results"][0]["source"] == "fallback"
    assert "private details" not in str(summary)


def test_existing_outputs_are_not_overwritten_or_followed_by_api_call(tmp_path):
    factory = MagicMock()
    with pytest.raises(FileExistsError):
        run_quality_check({}, send=True, output_dir=tmp_path, client_factory=factory)
    factory.assert_not_called()


def test_fast_guessing_distinguishes_minute_sum_from_unique_sources():
    case = next(case for case in build_quality_cases() if case.name == "brute_force_fast")
    payload, _ = build_ai_payload(case.incident, case.records)
    signal = next(item for item in payload["evidence"] if item["signal"] == "login_sources")
    assert signal["observed"] == 10
    assert payload["login_summary"]["distinct_outside_sources_10min"] == 2
    assert "sum of per-minute" in signal["meaning"]


def test_selection_rehearses_only_requested_scenarios_without_network():
    factory = MagicMock()
    summary = run_quality_check({}, scenario_names=["brute_force_fast", "brute_force_slow_success"], client_factory=factory)
    assert summary["scenarios_planned"] == 2
    assert [row["scenario"] for row in summary["results"]] == ["brute_force_fast", "brute_force_slow_success"]
    assert all(row["automatic_checks_passed"] for row in summary["results"])
    factory.assert_not_called()
