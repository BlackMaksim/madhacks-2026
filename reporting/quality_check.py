"""Six-case reporting rehearsal: offline by default, at most six calls with --send.

Automatic checks do not replace human review or measure detector accuracy.
Only prepared payloads and validated/template reports may be exported, never raw
records, private token maps, API settings, or internal audit snapshots.
"""

import argparse
import json
from pathlib import Path

from reporting.llm import ReportWriter, load_settings
from reporting.privacy import raw_values, serialize_payload
from reporting.quality_cases import build_quality_cases
from reporting.validation import ReportValidationError, validate_report


def run_quality_check(settings, send=False, output_dir=None, client_factory=None, scenario_names=None) -> dict:
    """Run fixtures sequentially and stop the paid pass at its first fallback.

    Existing output directories are refused before any API request to preserve
    earlier rehearsal outputs. Every result remains labeled by its true source.
    """
    cases = build_quality_cases()
    if scenario_names is not None:
        requested = set(scenario_names)
        if not requested or requested - {case.name for case in cases}:
            raise ValueError("Unknown or empty scenario selection")
        cases = [case for case in cases if case.name in requested]
    output = Path(output_dir) if output_dir is not None else None
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
    effective = dict(settings)
    effective["DEMO_OFFLINE"] = "0" if send else "1"
    effective["MAX_AI_CALLS"] = str(len(cases))
    writer = ReportWriter(effective, client_factory=client_factory)
    rows = []
    total_input = total_output = 0
    for case in cases:
        result = writer.generate(case.incident, case.records)
        payload = json.loads(result.audit["sent_payload"])
        issues = []
        try:
            # Check templates too; label them honestly instead of calling an
            # offline rehearsal a successful AI quality evaluation.
            _, warnings = validate_report(result.report, payload, raw_values(case.incident, case.records))
            issues.extend(warnings)
        except ReportValidationError as error:
            issues.append(str(error))
        row = {
            "scenario": case.name, "source": result.source, "error": result.error,
            "severity": result.report.severity, "category": result.report.likely_category,
            "leak_check_passed": result.audit["leak_check"]["passed"],
            "automatic_checks_passed": not issues, "check_issues": issues,
            "generation_warnings": result.warnings, "human_review": "pending",
        }
        rows.append(row)
        total_input += result.input_tokens or 0
        total_output += result.output_tokens or 0
        if output is not None:
            envelope = {
                **row, "fixture_origin": "hand_authored_synthetic_reporting_case",
                "model": result.model, "review_focus": case.review_focus,
                "payload": payload, "report": result.report.model_dump(),
            }
            (output / f"{case.name}.json").write_text(serialize_payload(envelope) + "\n", encoding="utf-8")
        if send and (result.source != "openai" or issues):
            break
    summary = {
        "mode": "live_ai_quality_pass" if send else "offline_template_rehearsal",
        "scenarios_planned": len(cases), "scenarios_processed": len(rows),
        "api_requests_attempted": writer.calls,
        "input_tokens_reported": total_input, "output_tokens_reported": total_output,
        "human_review": "pending", "results": rows,
    }
    if output is not None:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Six synthetic reporting scenarios; no API calls without --send")
    parser.add_argument("--send", action="store_true", help="Permit up to six paid Luna requests, no automatic retries")
    parser.add_argument("--out", type=Path, help="Create a NEW directory for labeled payloads/reports and summary")
    parser.add_argument("--scenario", action="append", choices=[case.name for case in build_quality_cases()], help="Run only this scenario; repeat to select several")
    args = parser.parse_args()
    try:
        summary = run_quality_check(load_settings(), send=args.send, output_dir=args.out, scenario_names=args.scenario)
    except FileExistsError:
        parser.error("Output directory already exists. Choose a new directory; earlier outputs were not overwritten.")
    except Exception as error:
        # Avoid echoing settings, API errors, or private audit values.
        print(json.dumps({"success": False, "error": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
