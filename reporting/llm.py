"""Bounded Luna incident reports, shared by the preview and reporter loop.

Default example is offline. --send explicitly opts into one real report for the
synthetic example. A ReportWriter has a per-instance request cap, not a durable
or monetary cap; restarting the process resets it. SDK retries are disabled.
"""

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
import json
import os
from pathlib import Path

from dotenv import dotenv_values
from openai import OpenAI

from reporting.check_openai_setup import setup_status
from reporting.fallback import fallback_report
from reporting.privacy import build_ai_payload, find_leaks, raw_values, serialize_payload
from reporting.prompts import SYSTEM_PROMPT
from reporting.schema import IncidentReport
from reporting.validation import ReportValidationError, validate_report


@dataclass
class ReportResult:
    report: IncidentReport
    source: str
    error: str | None
    warnings: list[str]
    audit: dict = field(repr=False)
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class ReportWriter:
    def __init__(self, settings, client_factory=None):
        self.settings = dict(settings)
        self.client_factory = client_factory or OpenAI
        self.calls = 0
        self._incident_calls = {}
        self._versions_attempted = set()
        self._previous_payloads = {}

    def generate(self, incident: dict, records: list[dict], save_audit=None) -> ReportResult:
        """Optionally persist audit snapshots before dispatch and after the result.

        save_audit must upsert by (incident_id, version). Callback failures
        propagate to the queue worker; a failure before dispatch prevents it.
        """
        history_key = (incident["incident_id"], incident["router_id"])
        previous = self._previous_payloads.get(history_key)
        payload, audit = (
            build_ai_payload(incident, records) if previous is None
            else build_ai_payload(incident, records, previous_payload=previous)
        )
        private_values = raw_values(incident, records)
        text = serialize_payload(payload)
        leaks = find_leaks(text, private_values)
        audit["leak_check"].update(passed=not leaks, found=leaks, blocked=bool(leaks), api_call_made=False, payload_status="prepared_not_sent")
        template = fallback_report(payload)
        if save_audit is not None:
            save_audit(deepcopy(audit))

        def remember():
            if not leaks and (previous is None or previous["report_version"] < payload["report_version"]):
                # Only our allowlisted measurement payload is cached. No raw
                # snapshot, private mapping, or generated AI prose enters history.
                self._previous_payloads[history_key] = deepcopy(payload)

        def fallback(reason):
            remember()
            return ReportResult(template, "fallback", reason, [], audit)

        if leaks:
            return fallback("privacy_check_blocked")
        configured = setup_status(self.settings)
        if not configured["offline_setting_valid"] or not configured["call_limit_setting_valid"]:
            return fallback("invalid_settings")
        if configured["offline_mode"]:
            return fallback("offline_mode")
        if not configured["api_key_present"]:
            return fallback("api_key_missing")
        if self.settings.get("OPENAI_MODEL") != "gpt-6-luna":
            return fallback("budget_model_requires_luna")
        if len(text) > 16000:
            return fallback("payload_too_large")
        limit = int(self.settings.get("MAX_AI_CALLS", "20"))
        if self.calls >= limit:
            return fallback("session_call_limit")
        incident_id = incident["incident_id"]  # Internal budget key; never sent.
        if self._incident_calls.get(incident_id, 0) >= 3:
            return fallback("incident_call_limit")
        request_key = (incident_id, incident["version"])
        if request_key in self._versions_attempted:
            return fallback("version_already_attempted")
        # Persist intent before dispatch. If the process dies here, this means
        # delivery is uncertain, not that the provider received the payload.
        audit["leak_check"]["payload_status"] = "dispatch_pending"
        if save_audit is not None:
            save_audit(deepcopy(audit))
        input_tokens = output_tokens = None
        try:
            with self.client_factory(
                api_key=self.settings["OPENAI_API_KEY"].strip(),
                base_url="https://api.openai.com/v1", timeout=30, max_retries=0,
            ) as client:
                # Count attempts before dispatch, including timeouts/errors.
                self.calls += 1
                self._incident_calls[incident_id] = self._incident_calls.get(incident_id, 0) + 1
                self._versions_attempted.add(request_key)
                audit["leak_check"].update(api_call_made=True, payload_status="request_attempted")
                response = client.responses.parse(
                    model="gpt-6-luna",
                    input=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": text}],
                    text_format=IncidentReport, max_output_tokens=2000,
                    reasoning={"effort": "none"}, service_tier="default", store=False,
                )
            if response.usage:
                input_tokens, output_tokens = response.usage.input_tokens, response.usage.output_tokens
            if response.status != "completed" or response.output_parsed is None:
                result = fallback("no_completed_report")
            else:
                checked, warnings = validate_report(response.output_parsed, payload, private_values)
                result = ReportResult(checked, "openai", None, warnings, audit, model="gpt-6-luna")
        except ReportValidationError as error:
            result = fallback(str(error))  # Fixed error codes only.
        except Exception as error:
            # SDK messages may contain raw request/response data. Never echo them.
            result = fallback(type(error).__name__)
        result.input_tokens, result.output_tokens = input_tokens, output_tokens
        if save_audit is not None:
            save_audit(deepcopy(audit))
        remember()
        return result


def load_settings() -> dict:
    """Load local reporting settings without printing values or modifying .env."""
    root = Path(__file__).resolve().parents[1]
    return {**dotenv_values(root / ".env", encoding="utf-8-sig"), **os.environ}


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview one synthetic incident report, offline unless --send")
    parser.add_argument("--example", action="store_true")
    parser.add_argument("--send", action="store_true", help="Opt into at most one paid Luna request for this example")
    args = parser.parse_args()
    if not args.example:
        parser.error("Use --example, optionally with --send")
    root = Path(__file__).resolve().parents[1]
    try:
        settings = load_settings()
        # These CLI flags affect this process only; the root .env is not edited.
        settings["DEMO_OFFLINE"] = "0" if args.send else "1"
        settings["MAX_AI_CALLS"] = "1"
        incident = json.loads((root / "contracts/examples/incident.json").read_text(encoding="utf-8"))
        records = json.loads((root / "reporting/examples/privacy_records.json").read_text(encoding="utf-8"))
        writer = ReportWriter(settings)
        result = writer.generate(incident, records)
    except Exception as error:
        print(json.dumps({"success": False, "error": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps({
        "source": result.source, "model": result.model, "error": result.error,
        "warnings": result.warnings, "api_requests_attempted": writer.calls,
        "input_tokens": result.input_tokens, "output_tokens": result.output_tokens,
        "leak_check_passed": result.audit["leak_check"]["passed"],
        "report": result.report.model_dump(),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
