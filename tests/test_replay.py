"""Saved-report selection, labels, exact matching, and tamper rejection."""

from copy import deepcopy
import json
import shutil

import pytest

from reporting import replay
from reporting.replay import RehearsalUnavailable, SCENARIOS, list_saved_reports, load_saved_report


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_selected_saved_examples_validate_and_keep_honest_source(scenario):
    saved = load_saved_report(scenario)
    display = saved.display_data()
    assert display["source"] == "saved_rehearsal"
    assert display["original_source"] == "openai"
    assert display["badge"] == "Saved from rehearsal"
    assert display["api_requests_attempted"] == 0
    assert display["human_review"] == "pending"
    if scenario.startswith("brute_force"):
        assert saved.origin_file.startswith("luna_v2_bruteforce/")


def test_current_payload_must_match_saved_payload_exactly():
    saved = load_saved_report("botnet_quiet")
    assert load_saved_report("botnet_quiet", expected_payload=saved.payload).report == saved.report
    other = deepcopy(saved.payload)
    other["evidence"][0]["observed"] += 1
    with pytest.raises(RehearsalUnavailable, match="saved_payload_mismatch"):
        load_saved_report("botnet_quiet", expected_payload=other)


def test_arbitrary_file_path_cannot_be_selected():
    with pytest.raises(RehearsalUnavailable, match="unknown_rehearsal_scenario"):
        load_saved_report("../../.env")


def test_modified_saved_file_is_rejected(tmp_path, monkeypatch):
    copied = tmp_path / "reports"
    shutil.copytree(replay._REPORTS_DIR, copied)
    monkeypatch.setattr(replay, "_REPORTS_DIR", copied)
    path = copied / "luna_v1/botnet_quiet.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["report"]["severity"] = "low"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(RehearsalUnavailable, match="rehearsal_file_changed"):
        load_saved_report("botnet_quiet")


def test_json_formatting_and_line_endings_do_not_break_replay(tmp_path, monkeypatch):
    copied = tmp_path / "reports"
    shutil.copytree(replay._REPORTS_DIR, copied)
    monkeypatch.setattr(replay, "_REPORTS_DIR", copied)
    path = copied / "luna_v1/botnet_quiet.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    path.write_bytes(json.dumps(envelope, indent=2).replace("\n", "\r\n").encode("utf-8"))
    assert load_saved_report("botnet_quiet").source == "saved_rehearsal"


def test_missing_artifact_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(replay, "_REPORTS_DIR", tmp_path)
    with pytest.raises(RehearsalUnavailable, match="saved_example_unavailable_or_invalid"):
        load_saved_report("botnet_quiet")


def test_manifest_cannot_select_a_path_outside_report_directory(tmp_path, monkeypatch):
    manifest = {"schema_version": "rehearsal_manifest_v1", "cases": {
        "botnet_quiet": {"path": "../outside.json", "sha256": "unused"},
    }}
    (tmp_path / "replay_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(replay, "_REPORTS_DIR", tmp_path)
    with pytest.raises(RehearsalUnavailable, match="invalid_rehearsal_path"):
        load_saved_report("botnet_quiet")


def test_list_retains_known_historical_note():
    rows = list_saved_reports()
    assert len(rows) == 6
    loud = next(row for row in rows if row["scenario"] == "botnet_loud")
    assert loud["known_notes"]


@pytest.mark.parametrize("scenario", ["botnet_loud", "brute_force_fast", "brute_force_slow_success"])
def test_wording_edits_are_labeled_and_original_response_is_preserved(scenario):
    saved = load_saved_report(scenario)
    original = saved.report.model_dump()
    display = saved.display_data()
    assert display["display_wording_edited"] is True
    assert display["display_edit_notes"]
    assert display["original_report"] == original == saved.report.model_dump()
    assert display["report"] != original
    assert display["human_review"] == "pending"
    assert display["api_requests_attempted"] == 0
    if scenario == "botnet_loud":
        assert not any("incident token" in action for action in display["report"]["customer_actions"])
    else:
        evidence = next(item for item in display["report"]["evidence"] if item["signal"] == "login_sources")
        assert "summed per-minute" in evidence["interpretation"]
        assert "does not establish" in evidence["interpretation"]
        assert "no successful outside login" not in display["report"]["behavior_explanation"]


@pytest.mark.parametrize("scenario", ["botnet_quiet", "new_device", "unknown_anomaly"])
def test_unedited_examples_keep_the_exact_original_report(scenario):
    display = load_saved_report(scenario).display_data()
    assert not display["display_wording_edited"]
    assert display["report"] == display["original_report"]
