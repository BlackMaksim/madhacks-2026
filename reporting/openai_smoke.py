"""One explicitly requested, bounded Structured Outputs connectivity test.

Without --send this makes no requests. --send opts into one synthetic test even
while DEMO_OFFLINE=1; it does not change the reporter's offline configuration.
Each invocation is independent, not a session-wide or dollar-budget limiter.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from openai import OpenAI
from pydantic import BaseModel, ConfigDict

from reporting.check_openai_setup import setup_status


class ConnectionCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["ok"]


class SmokeTestError(Exception):
    """A fixed, non-sensitive failure label."""


def run_smoke_test(settings, client_factory=None) -> dict:
    """Send one tiny request. No telemetry, tools, retries, or model escalation."""
    configured = setup_status(settings)
    if not configured["api_key_present"]:
        raise SmokeTestError("api_key_missing")
    if settings.get("OPENAI_MODEL") != "gpt-6-luna":
        raise SmokeTestError("smoke_test_requires_luna")
    if not configured["call_limit_setting_valid"]:
        raise SmokeTestError("invalid_call_limit_setting")
    factory = client_factory or OpenAI
    with factory(
        api_key=settings["OPENAI_API_KEY"].strip(),
        base_url="https://api.openai.com/v1",
        max_retries=0,
        timeout=20,
    ) as client:
        response = client.responses.parse(
            model="gpt-6-luna",
            input="This is a connection test using synthetic data. Return status ok.",
            text_format=ConnectionCheck,
            max_output_tokens=128,
            reasoning={"effort": "none"},
            service_tier="default",
            store=False,
        )
    if response.status != "completed":
        raise SmokeTestError("response_not_completed")
    if response.output_parsed is None:
        raise SmokeTestError("no_parsed_response")
    parsed = ConnectionCheck.model_validate(response.output_parsed)
    usage = response.usage
    return {
        "success": True,
        "model": "gpt-6-luna",
        "parsed_status": parsed.status,
        "api_requests_attempted": 1,
        "automatic_retries": 0,
        "input_tokens": usage.input_tokens if usage else None,
        "output_tokens": usage.output_tokens if usage else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="One small, paid Luna API test; no request without --send")
    parser.add_argument("--send", action="store_true", help="Explicitly send ONE synthetic API request, independent of demo offline mode")
    args = parser.parse_args()
    if not args.send:
        print(json.dumps({
            "mode": "dry_run", "api_calls": 0, "model": "gpt-6-luna",
            "max_output_tokens": 128, "automatic_retries": 0,
            "next_step": "Use --send only when ready for one paid synthetic request",
        }, indent=2))
        return
    try:
        path = Path(__file__).resolve().parents[1] / ".env"
        settings = {**dotenv_values(path, encoding="utf-8-sig"), **os.environ}
        result = run_smoke_test(settings)
    except Exception as error:
        # Never echo server messages, request headers, settings, or credentials.
        safe_code = str(error) if isinstance(error, SmokeTestError) else type(error).__name__
        result = {"success": False, "error": safe_code, "automatic_retries": 0}
        status = getattr(error, "status_code", None)
        if type(status) is int:
            result["http_status"] = status
        print(json.dumps(result, indent=2))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
