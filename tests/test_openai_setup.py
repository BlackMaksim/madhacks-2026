"""Local setup checker tests: no credentials, requests, or real .env needed."""

import json
from pathlib import Path

import pytest
from dotenv import dotenv_values

from reporting.check_openai_setup import setup_status


def test_empty_settings_stay_offline():
    status = setup_status({})
    assert status["api_key_present"] is False
    assert status["model_configured"] is False
    assert status["offline_mode"] is True
    assert status["api_calls"] == 0


def test_key_is_never_returned_and_presence_does_not_claim_authentication():
    marker = "synthetic-test-credential-not-real"
    status = setup_status({"OPENAI_API_KEY": marker, "OPENAI_MODEL": "example-model"})
    assert status["api_key_present"] is True
    assert status["model_configured"] is True
    assert status["api_authentication_tested"] is False
    assert marker not in json.dumps(status)


def test_placeholder_is_not_considered_a_configured_key():
    assert setup_status({"OPENAI_API_KEY": "your-key-here"})["api_key_present"] is False


@pytest.mark.parametrize("value", ["0", "61", "not-a-number"])
def test_invalid_limit_is_identified_without_echoing_input(value):
    status = setup_status({"MAX_AI_CALLS": value})
    assert status["call_limit_setting_valid"] is False


def test_invalid_offline_setting_is_identified():
    assert setup_status({"DEMO_OFFLINE": "maybe"})["offline_setting_valid"] is False


def test_committable_example_contains_no_api_key():
    path = Path(__file__).resolve().parents[1] / "reporting/.env.example"
    values = dotenv_values(path, interpolate=False)
    # Assert only a boolean so a failed test does not echo a credential.
    contains_credential = bool((values.get("OPENAI_API_KEY") or "").strip())
    assert contains_credential is False, "Remove the credential from reporting/.env.example"
