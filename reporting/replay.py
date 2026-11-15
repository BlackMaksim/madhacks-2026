"""Offline viewer for saved synthetic AI reports; never makes an API request.

This is a separate rehearsal source, not an automatic replacement for a live
incident report. Passing expected_payload requires an exact canonical match.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from reporting.privacy import find_leaks, serialize_payload
from reporting.schema import IncidentReport
from reporting.validation import validate_report


_REPORTS_DIR = Path(__file__).resolve().parents[1] / "contracts/examples/reports"
SCENARIOS = (
    "botnet_quiet", "botnet_loud", "brute_force_fast",
    "brute_force_slow_success", "new_device", "unknown_anomaly",
)


class RehearsalUnavailable(ValueError):
    """Fixed reason codes only; never echo private payloads or file contents."""


@dataclass(frozen=True)
class SavedRehearsal:
    scenario: str
    report: IncidentReport
    payload: dict
    origin_file: str
    known_notes: tuple[str, ...]
    source: str = "saved_rehearsal"
    original_source: str = "openai"
    badge: str = "Saved from rehearsal"
    model: str = "gpt-6-luna"
    human_review: str = "pending"

    def display_data(self) -> dict:
        """Keep source metadata beside the report when handing it to a UI."""
        return {
            "source": self.source, "original_source": self.original_source,
            "badge": self.badge, "scenario": self.scenario, "model": self.model,
            "origin_file": self.origin_file, "human_review": self.human_review,
            "known_notes": list(self.known_notes), "api_requests_attempted": 0,
            "payload": self.payload, "report": self.report.model_dump(),
        }


def load_saved_report(scenario: str, expected_payload: dict | None = None) -> SavedRehearsal:
    """Load only selected, hash-checked examples and validate them again locally.

    Unknown, altered, invalid, or mismatching examples raise RehearsalUnavailable.
    The hashes detect changes relative to the repository manifest; they are not
    a signature or proof of who originally generated a report.
    """
    if scenario not in SCENARIOS:
        raise RehearsalUnavailable("unknown_rehearsal_scenario")
    try:
        manifest = json.loads((_REPORTS_DIR / "replay_manifest.json").read_text(encoding="utf-8"))
        if manifest["schema_version"] != "rehearsal_manifest_v1":
            raise RehearsalUnavailable("unsupported_rehearsal_manifest")
        entry = manifest["cases"][scenario]
        path = (_REPORTS_DIR / entry["path"]).resolve()
        if not path.is_relative_to(_REPORTS_DIR.resolve()) or path.suffix != ".json":
            raise RehearsalUnavailable("invalid_rehearsal_path")
        envelope = json.loads(path.read_bytes())
        # Hash canonical JSON so Windows/Linux line endings and pretty-printing
        # do not invalidate an otherwise identical repository checkout.
        content_hash = hashlib.sha256(serialize_payload(envelope).encode("utf-8")).hexdigest()
        if content_hash != entry["sha256"]:
            raise RehearsalUnavailable("rehearsal_file_changed")
        if (envelope["scenario"] != scenario or envelope["source"] != "openai"
                or envelope["model"] != "gpt-6-luna" or envelope["error"] is not None):
            raise RehearsalUnavailable("invalid_rehearsal_provenance")
        payload = envelope["payload"]
        if expected_payload is not None and serialize_payload(payload) != serialize_payload(expected_payload):
            raise RehearsalUnavailable("saved_payload_mismatch")
        if find_leaks(serialize_payload(payload), set()):
            raise RehearsalUnavailable("address_in_saved_payload")
        report = IncidentReport.model_validate(envelope["report"])
        checked, warnings = validate_report(report, payload, set())
        if warnings or checked != report:
            raise RehearsalUnavailable("saved_report_requires_correction")
        notes = (
            ("The historical customer action mentions a local incident token; it is not a customer-facing support reference.",)
            if scenario == "botnet_loud" else ()
        )
        return SavedRehearsal(scenario, report, payload, entry["path"], notes)
    except RehearsalUnavailable:
        raise
    except Exception:
        raise RehearsalUnavailable("saved_example_unavailable_or_invalid") from None


def list_saved_reports() -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        saved = load_saved_report(scenario)
        rows.append({
            "scenario": scenario, "source": saved.source, "badge": saved.badge,
            "severity": saved.report.severity, "category": saved.report.likely_category,
            "human_review": saved.human_review, "known_notes": list(saved.known_notes),
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="View saved rehearsal reports without API, credentials, or a database")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true", help="List six selected saved examples")
    group.add_argument("--scenario", choices=SCENARIOS, help="View one saved example with its payload")
    args = parser.parse_args()
    try:
        data = load_saved_report(args.scenario).display_data() if args.scenario else {
            "mode": "saved_rehearsal_viewer", "api_requests_attempted": 0,
            "examples": list_saved_reports(),
        }
    except RehearsalUnavailable as error:
        print(json.dumps({"success": False, "error": str(error)}))
        raise SystemExit(1) from None
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
