"""Check that teammate example files match our shared data models."""

import json
from pathlib import Path

from contracts.models import Incident, ScoreRow


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = PROJECT_ROOT / "contracts" / "examples"


def test_score_row_example_matches_contract():
    example_path = EXAMPLES_DIR / "score_row.json"
    data = json.loads(example_path.read_text(encoding="utf-8"))

    ScoreRow.model_validate(data)


def test_incident_example_matches_contract():
    example_path = EXAMPLES_DIR / "incident.json"
    data = json.loads(example_path.read_text(encoding="utf-8"))

    Incident.model_validate(data)