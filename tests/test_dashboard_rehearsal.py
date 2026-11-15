"""Exercise the actual tab renderer against old and current replay dictionaries.

Extract only the renderer so importing Streamlit's whole app cannot initialize
the demo database or start its timed fragments during this compatibility test.
"""

import ast
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reporting.replay import SCENARIOS, RehearsalUnavailable, load_saved_report


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("legacy", [False, True])
def test_saved_tab_handles_cached_legacy_and_current_replay(scenario, legacy):
    path = Path(__file__).resolve().parents[1] / "app/dashboard.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    renderer = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_render_saved_rehearsal_tab")
    saved = load_saved_report(scenario).display_data()
    if legacy:
        saved["report"] = deepcopy(saved["original_report"])
        for key in ("original_report", "display_wording_edited", "display_edit_notes"):
            saved.pop(key)
    st = MagicMock()
    st.selectbox.return_value = scenario
    replay = SimpleNamespace(SCENARIOS=SCENARIOS, RehearsalUnavailable=RehearsalUnavailable,
                             load_saved_report=MagicMock())
    replay.load_saved_report.return_value.display_data.return_value = saved
    body = MagicMock()
    namespace = {"st": st, "replay": replay, "_render_report_body": body}
    module = ast.Module(body=[renderer], type_ignores=[])
    exec(compile(module, str(path), "exec"), namespace)
    namespace["_render_saved_rehearsal_tab"]()
    body.assert_called_once_with(saved["report"])
    st.success.assert_called_once_with("Saved from rehearsal")
    restart_warning = any("Restart the dashboard" in call.args[0] for call in st.warning.call_args_list)
    assert restart_warning is legacy
