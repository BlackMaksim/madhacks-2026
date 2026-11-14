"""Test the API request boundary with mocks only; no real key or spending."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reporting.openai_smoke import ConnectionCheck, SmokeTestError, run_smoke_test


@pytest.fixture
def settings():
    return {"OPENAI_API_KEY": "synthetic-not-a-real-key", "OPENAI_MODEL": "gpt-6-luna", "DEMO_OFFLINE": "1", "MAX_AI_CALLS": "20"}


@pytest.fixture
def factory():
    mocked = MagicMock()
    mocked.return_value.__enter__.return_value.responses.parse.return_value = SimpleNamespace(
        status="completed", output_parsed=ConnectionCheck(status="ok"),
        usage=SimpleNamespace(input_tokens=100, output_tokens=10),
    )
    return mocked


def test_single_request_is_bounded_and_does_not_return_key(settings, factory):
    result = run_smoke_test(settings, factory)
    factory.assert_called_once()
    assert factory.call_args.kwargs["max_retries"] == 0
    assert factory.call_args.kwargs["base_url"] == "https://api.openai.com/v1"
    request = factory.return_value.__enter__.return_value.responses.parse
    request.assert_called_once()
    assert request.call_args.kwargs["model"] == "gpt-6-luna"
    assert request.call_args.kwargs["max_output_tokens"] == 128
    assert request.call_args.kwargs["reasoning"] == {"effort": "none"}
    assert request.call_args.kwargs["store"] is False
    assert "tools" not in request.call_args.kwargs
    assert result["parsed_status"] == "ok"
    assert settings["OPENAI_API_KEY"] not in str(result)


@pytest.mark.parametrize(("field", "value"), [("OPENAI_API_KEY", ""), ("OPENAI_MODEL", "gpt-6-astra"), ("MAX_AI_CALLS", "0")])
def test_invalid_config_never_creates_client(settings, factory, field, value):
    settings[field] = value
    with pytest.raises(SmokeTestError):
        run_smoke_test(settings, factory)
    factory.assert_not_called()


@pytest.mark.parametrize(("status", "parsed"), [("incomplete", None), ("completed", None)])
def test_incomplete_or_unparsed_response_is_not_success(settings, factory, status, parsed):
    factory.return_value.__enter__.return_value.responses.parse.return_value = SimpleNamespace(status=status, output_parsed=parsed)
    with pytest.raises(SmokeTestError):
        run_smoke_test(settings, factory)


def test_request_error_is_not_retried(settings, factory):
    request = factory.return_value.__enter__.return_value.responses.parse
    request.side_effect = RuntimeError("synthetic error")
    with pytest.raises(RuntimeError):
        run_smoke_test(settings, factory)
    request.assert_called_once()
