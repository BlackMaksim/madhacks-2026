"""Check that teammate example files match our shared data models."""

from pathlib import Path

import json

import pytest

from contracts.models import Incident, Record, ScoreRow
from reporting.fallback import fallback_report
from reporting.schema import IncidentReport


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = PROJECT_ROOT / "contracts" / "examples"


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("record_normal.json", Record),
        ("record_botnet_quiet.json", Record),
        ("score_row.json", ScoreRow),
        ("incident.json", Incident),
        ("report.json", IncidentReport),
    ],
)
def test_example_matches_contract(filename, model):
    model.model_validate_json((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))


def test_ai_input_example_works_with_production_fallback():
    payload = json.loads((EXAMPLES_DIR / "ai_input.json").read_text(encoding="utf-8"))
    report = fallback_report(payload)
    assert report.severity == payload["detector"]["severity"]
