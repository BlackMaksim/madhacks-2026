"""Integration checks for one live engine path using the supplied stubs."""

from app import db
from app.engine import process_tick, warmup_buffer, chart_seed_records, new_incident_manager
from detection.detector import load_bundle
from detection.incidents import IncidentManager
from reporting.reporter import process_one
from simulator.fleet import Fleet
from app.engine import initialize_fleet
from datetime import datetime, timedelta


def test_restart_advances_charts_and_classifier_without_replacing_history(tmp_path, monkeypatch):
    """Reproduce retained future rows masking a restarted engine's live output."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "restart.db")
    db.init_db()
    fleet, buffer = initialize_fleet()
    bundle = load_bundle("stub")
    buffer, _ = process_tick(fleet, buffer, bundle, new_incident_manager())
    old_record = db.recent_records("R-107", 1)[0]
    future_ts = (datetime.fromisoformat(old_record["ts"]) + timedelta(days=7)).isoformat()
    retained_record = dict(old_record, ts=future_ts, dns_failures=12345)
    retained_score = dict(db.latest_score("R-107"), ts=future_ts)
    db.insert_records([retained_record])
    db.insert_scores([retained_score])

    fleet, buffer = initialize_fleet()
    expected = (datetime.fromisoformat(future_ts) + timedelta(minutes=1)).isoformat()
    assert fleet.now.isoformat() == expected
    assert db.recent_records("R-107", 1) == [retained_record]
    buffer, _ = process_tick(fleet, buffer, bundle, new_incident_manager())
    assert db.recent_records("R-107", 1)[0]["ts"] == expected
    assert db.recent_scores("R-107", 1)[0]["ts"] == expected
    assert db.latest_score("R-107")["ts"] == expected
    assert db.recent_records("R-107", 2)[0] == retained_record


def test_clock_high_water_mark_includes_partial_tick(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "partial.db")
    db.init_db()
    assert db.latest_simulation_timestamp() is None
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO router_status (router_id, ts, status, verdict, anomaly_pct) "
            "VALUES ('R-107', '2026-12-01T12:00:00', 'healthy', 'normal', 0.1)"
        )
    assert db.latest_simulation_timestamp() == "2026-12-01T12:00:00"


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

    # A restarted manager must queue a fresh report rather than reuse the done
    # request/report under INC-0001, even for a different router.
    old_id = incident["incident_id"]
    monkeypatch.setenv("STUB_ATTACK_ROUTERS", "R-103")
    incidents = new_incident_manager()
    for _ in range(3):
        buffer, incidents = process_tick(fleet, buffer, bundle, incidents)
    new_incident = db.open_or_latest_incident("R-103")
    assert new_incident["incident_id"] != old_id
    assert db.get_incident(old_id)["router_id"] == "R-107"
    assert db.latest_report(old_id) == report
    assert process_one(db) is True
    assert db.latest_report(new_incident["incident_id"])["source"] == "fallback"

    next_minute = fleet.now.strftime("%Y-%m-%dT%H:%M:%S")
    db.insert_command("reset", None)
    buffer, incidents = process_tick(fleet, buffer, bundle, incidents)

    assert db.pending_commands() == []
    assert len(db.router_ids()) == 12
    assert db.latest_status()[0]["ts"] == next_minute
    assert incidents.open_incidents() == []
