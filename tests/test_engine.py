"""Integration checks for one live engine path using the supplied stubs."""

from app import db
from app.engine import process_tick, warmup_buffer, chart_seed_records
from detection.detector import load_bundle
from detection.incidents import IncidentManager
from reporting.reporter import process_one
from simulator.fleet import Fleet


def test_engine_persists_scores_status_truth_and_report_request(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "engine-test.db")
    monkeypatch.setenv("STUB_ATTACK_ROUTERS", "R-107")
    db.init_db()

    fleet = Fleet(n_routers=12, seed=7)
    buffer = warmup_buffer(fleet)
    db.insert_records(chart_seed_records(buffer))
    bundle = load_bundle("stub")
    incidents = IncidentManager()

    for _ in range(3):
        buffer, incidents = process_tick(fleet, buffer, bundle, incidents)

    assert len(db.router_ids()) == 12
    assert len(db.recent_scores("R-107", 3)) == 3
    assert db.latest_status()[6]["router_id"] == "R-107"

    incident = db.open_or_latest_incident("R-107")
    assert incident is not None
    assert incident["incident_type"] == "botnet"
    assert incident["severity"] == "high"
    assert process_one(db) is True

    report = db.latest_report(incident["incident_id"])
    audit = db.latest_audit(incident["incident_id"])
    assert report["source"] == "fallback"
    assert report["report"]["likely_category"] == "botnet_infection"
    assert audit["leak_check"]["passed"] is True
    assert audit["leak_check"]["api_call_made"] is False
