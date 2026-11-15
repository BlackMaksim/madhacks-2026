"""Exercise the real privacy renderer without initializing the live application."""

import ast
import json
from pathlib import Path

import pytest
from unittest.mock import MagicMock

import pandas as pd

from reporting.privacy import build_ai_payload


def render_panel(audit, report=None):
    path = Path(__file__).resolve().parents[1] / "app/dashboard.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    renderer = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_render_privacy_panel")
    st = MagicMock()
    namespace = dict(st=st, pd=pd, json=json)
    exec(compile(ast.Module(body=[renderer], type_ignores=[]), str(path), "exec"), namespace)
    namespace["_render_privacy_panel"](audit, report)
    return st


@pytest.fixture
def audit():
    root = Path(__file__).resolve().parents[1]
    incident = json.loads((root / "contracts/examples/incident.json").read_text())
    records = json.loads((root / "reporting/examples/privacy_records.json").read_text())
    _, value = build_ai_payload(incident, records)
    value["version"] = 2
    return value


@pytest.mark.parametrize("state,expected", [
    ("prepared_not_sent", "not sent"),
    ("dispatch_pending", "Dispatch pending"),
    ("request_attempted", "request attempted"),
])
def test_privacy_panel_uses_matching_audit_and_collapses_technical_details(audit, state, expected):
    audit["leak_check"]["payload_status"] = state
    app = render_panel(audit)
    assert app.success.call_count == 1
    assert any("version: 2" in call.args[0] for call in app.caption.call_args_list)
    assert any(expected in call.args[0] for call in app.caption.call_args_list)
    assert app.table.call_args.args[0].loc["Router reference", "This report"] == "ROUTER_A"
    displayed_payload = json.loads(app.code.call_args_list[0].args[0])
    assert displayed_payload == json.loads(audit["sent_payload"])
    assert displayed_payload["evidence"][0]["observed"] == 41
    assert app.expander.call_count == 2
    assert all(call.kwargs["expanded"] is False for call in app.expander.call_args_list)
    # The original audit and prepared input remain available for inspection.
    assert app.json.call_count == 4
    assert any(call.args[0] == audit["raw_snapshot"] for call in app.json.call_args_list)


def test_privacy_panel_blocked_state_never_shows_green_success(audit):
    audit["leak_check"].update(passed=True, blocked=True)
    app = render_panel(audit)
    assert not app.success.called
    assert "blocked" in app.error.call_args.args[0]


def test_privacy_panel_missing_legacy_and_unreadable_data(audit):
    assert "matching privacy audit" in render_panel(None).info.call_args.args[0]
    audit["leak_check"] = {}
    audit["sent_payload"] = "invalid JSON"
    app = render_panel(audit)
    assert not app.success.called
    assert app.warning.call_count == 2
    assert any("unavailable" in call.args[0] for call in app.caption.call_args_list)


@pytest.mark.parametrize("source,expected", [("openai", "OpenAI · gpt-6-luna"), ("fallback", "Local template")])
def test_card_report_source_is_taken_from_matching_report(audit, source, expected):
    report = dict(incident_id=audit.get("incident_id"), version=2, source=source, model="gpt-6-luna")
    app = render_panel(audit, report)
    assert app.table.call_args.args[0].loc["Report source", "This report"] == expected
    report["version"] = 1
    app = render_panel(audit, report)
    assert app.table.call_args.args[0].loc["Report source", "This report"] == "Unavailable"
