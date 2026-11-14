"""Integration checks for the SQLite adapter used by the engine and reporter."""

import pytest

from app import db


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Give each test a fresh SQLite file instead of touching live.db."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test-live.db")
    db.init_db()
    return db


def test_database_round_trip_for_engine_reporter_and_dashboard(isolated_db):
    store = isolated_db
    ts = "2026-11-14T19:47:00"

    record = {
        "router_id": "R-TEST",
        "ts": ts,
        "customer_name": "Synthetic Test Customer",
        "dns_failures": 3,
        "new_domains": 2,
    }
    store.insert_records([record])
    assert store.recent_records("R-TEST", 5) == [record]

    score = {
        "router_id": "R-TEST",
        "ts": ts,
        "anomaly_score": 0.6,
        "anomaly_pct": 0.998,
        "flagged": True,
        "p_normal": 0.05,
        "p_benign_unusual": 0.10,
        "p_brute_force": 0.04,
        "p_botnet": 0.81,
        "predicted_class": "botnet",
        "class_conf": 0.81,
        "verdict": "known_attack",
    }
    store.insert_scores([score])
    assert store.latest_score("R-TEST")["predicted_class"] == "botnet"
    assert len(store.recent_scores("R-TEST", 5)) == 1

    status = {
        "router_id": "R-TEST",
        "ts": ts,
        "status": "critical",
        "verdict": "known_attack",
        "anomaly_pct": 0.998,
        "open_incident_id": "INC-TEST",
    }
    store.upsert_status([status])
    assert store.router_ids() == ["R-TEST"]
    assert store.latest_status()[0]["status"] == "critical"

    incident = {
        "incident_id": "INC-TEST",
        "router_id": "R-TEST",
        "status": "open",
        "opened_ts": ts,
        "last_ts": ts,
        "closed_ts": None,
        "version": 1,
        "incident_type": "botnet",
        "severity": "high",
        "verdict_counts": {"known_attack": 3},
        "minutes_suspicious": 3,
        "detector": {"predicted_class": "botnet"},
        "evidence": [],
        "trend_per_5_min": {},
        "flags": {},
        "login_summary": {},
    }
    store.upsert_incident(incident)
    assert store.get_incident("INC-TEST") == incident
    assert store.open_or_latest_incident("R-TEST")["incident_id"] == "INC-TEST"

    store.insert_truth(
        [{"router_id": "R-TEST", "ts": ts, "label": "botnet", "scenario": "botnet", "phase": "quiet"}]
    )

    store.request_report("INC-TEST", 1)
    store.request_report("INC-TEST", 1)  # Duplicate requests should be ignored.
    request = store.claim_report_request()
    assert request == {"incident_id": "INC-TEST", "version": 1}
    assert store.claim_report_request() is None

    audit = {
        "incident_id": "INC-TEST",
        "version": 1,
        "created_at": ts,
        "raw_snapshot": {"router_id": "R-TEST"},
        "sent_payload": {"incident_token": "INCIDENT_TEST"},
        "transformations": ["router_id replaced with a token"],
        "token_map": {"ROUTER_A": "R-TEST"},
        "leak_check": {"passed": True, "blocked": False},
        "bytes_raw": 100,
        "bytes_sent": 50,
    }
    store.save_audit(audit)
    saved_audit = store.latest_audit("INC-TEST")
    assert saved_audit["sent_payload"] == audit["sent_payload"]
    assert saved_audit["leak_check"]["passed"] is True

    report = {"executive_summary": "Synthetic test report", "severity": "high"}
    store.save_report("INC-TEST", 1, "fallback", None, 12, None, report)
    saved_report = store.latest_report("INC-TEST")
    assert saved_report["source"] == "fallback"
    assert saved_report["report"] == report
    store.finish_report_request("INC-TEST", 1, "done")

    summary = store.fleet_summary()
    assert summary["routers_monitored"] == 1
    assert summary["open_incidents"] == 1
    assert summary["template_reports"] == 1

    store.reset_db()
    assert store.router_ids() == []
    assert store.fleet_summary()["open_incidents"] == 0
