import pandas as pd

from detection.incidents import IncidentManager

TS = pd.date_range("2026-11-14T18:00:00", periods=400, freq="min").strftime("%Y-%m-%dT%H:%M:%S")

NORMAL = dict(verdict="normal", predicted_class="normal", anomaly_pct=0.5)
BOTNET = dict(verdict="known_attack", predicted_class="botnet", anomaly_pct=0.998)
BRUTE = dict(verdict="known_attack", predicted_class="brute_force", anomaly_pct=0.998)
BENIGN = dict(verdict="unusual_benign", predicted_class="benign_unusual", anomaly_pct=0.997)
WATCH = dict(verdict="watch", predicted_class="botnet", anomaly_pct=0.9)


def run(mgr, kinds, rid="R-107", start=0, feats=None):
    events = []
    for i, k in enumerate(kinds):
        s = {"router_id": rid, "ts": TS[start + i], "p_botnet": 0.8, **k}
        events.append(mgr.update(s, feats or {}))
    return events


def opened(events):
    return [e for e in events if e and e["event"] == "opened"]


def test_opens_on_third_suspicious_of_five():
    ev = run(IncidentManager(), [BOTNET, NORMAL, BOTNET, BOTNET])
    assert [e and e["event"] for e in ev] == [None, None, None, "opened"]
    inc = ev[-1]["incident"]
    assert inc["incident_type"] == "botnet" and inc["severity"] == "high" and inc["version"] == 1
    assert inc["verdict_counts"] == {"known_attack": 3}


def test_two_of_five_does_not_open():
    assert not opened(run(IncidentManager(), [BOTNET, NORMAL, NORMAL, BOTNET, NORMAL, NORMAL]))


def test_no_duplicate_while_open():
    ev = run(IncidentManager(), [BOTNET] * 30)
    assert len(opened(ev)) == 1
    assert {e["incident"]["incident_id"] for e in ev if e} == {"INC-0001"}


def test_closes_after_20_calm_minutes():
    mgr = IncidentManager()
    ev = run(mgr, [BOTNET] * 3 + [NORMAL] * 20)
    assert ev[-1]["event"] == "closed" and ev[-1]["incident"]["status"] == "resolved"
    assert ev[-2] is None
    assert mgr.open_incidents() == []


def test_reopens_within_30_minutes():
    mgr = IncidentManager()
    run(mgr, [BOTNET] * 3 + [NORMAL] * 20)
    ev = run(mgr, [NORMAL] * 5 + [BOTNET], start=23)
    assert ev[-1]["event"] == "escalated"
    assert ev[-1]["incident"]["incident_id"] == "INC-0001" and ev[-1]["incident"]["version"] == 2


def test_new_incident_after_30_minutes():
    mgr = IncidentManager()
    run(mgr, [BOTNET] * 3 + [NORMAL] * 20)
    ev = run(mgr, [NORMAL] * 40 + [BOTNET] * 3, start=23)
    assert opened(ev)[0]["incident"]["incident_id"] == "INC-0002"


def test_loud_phase_escalates_and_version_caps_at_3():
    mgr = IncidentManager()
    run(mgr, [BOTNET] * 3)
    loud = {"outbound_conns_lr10": 3.0}
    ev = run(mgr, [BOTNET], start=3, feats=loud)
    assert ev[0]["event"] == "escalated"
    assert ev[0]["incident"]["severity"] == "critical" and ev[0]["incident"]["version"] == 2
    # A quiet minute afterwards must not lower severity.
    ev = run(mgr, [BOTNET], start=4)
    assert ev[0]["event"] == "updated" and ev[0]["incident"]["severity"] == "critical"
    # Close and reopen twice: version stops at 3.
    run(mgr, [NORMAL] * 20, start=5)
    run(mgr, [BOTNET], start=25)
    run(mgr, [NORMAL] * 20, start=26)
    ev = run(mgr, [BOTNET], start=46)
    assert ev[0]["incident"]["version"] == 3


def test_more_serious_type_takes_over_after_3_minutes():
    mgr = IncidentManager()
    ev = run(mgr, [BENIGN] * 6 + [BOTNET] * 3)
    assert opened(ev)[0]["incident"]["incident_type"] == "unusual_benign"
    assert opened(ev)[0]["incident"]["severity"] == "low"
    assert ev[-1]["event"] == "escalated" and ev[-1]["incident"]["incident_type"] == "botnet"


def test_five_watch_minutes_open():
    ev = run(IncidentManager(), [WATCH] * 5)
    assert ev[-1]["event"] == "opened" and ev[-1]["incident"]["incident_type"] == "botnet"


def test_brute_force_success_is_high():
    feats = {"success_after_fails_w10": 1, "failed_logins_wan_w10": 25}
    ev = run(IncidentManager(), [BRUTE] * 3, feats=feats)
    assert ev[-1]["incident"]["severity"] == "high"


def test_incident_matches_contract_keys():
    import json
    example = json.load(open("contracts/examples/incident.json"))
    inc = run(IncidentManager(), [BOTNET] * 3)[-1]["incident"]
    assert set(inc) == set(example)
    assert set(inc["detector"]) == set(example["detector"])
    assert set(inc["flags"]) == set(example["flags"])
    assert set(inc["login_summary"]) == set(example["login_summary"])
