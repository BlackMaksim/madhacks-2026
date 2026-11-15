import pandas as pd

from detection import config as C
from detection.evaluate import false_incidents, score_episodes

EPISODES = pd.DataFrame([{"episode_id": "E1", "router_id": "R-001", "scenario": "botnet_scan", "label": "botnet",
                          "start_ts": "2026-11-02T12:00:00", "end_ts": "2026-11-02T12:30:00",
                          "loud_start_ts": "2026-11-02T12:20:00", "intensity": 1.0, "success": ""}])


def ev(ts, event="opened", t="botnet", sev="high", rid="R-001", inc="INC-0001"):
    return {"router_id": rid, "ts": ts, "event": event, "incident_id": inc, "incident_type": t, "severity": sev}


def test_episode_caught_early_with_delay():
    events = pd.DataFrame([ev("2026-11-02T12:07:00"), ev("2026-11-02T12:22:00", "escalated", sev="critical")])
    r = score_episodes(events, EPISODES).iloc[0]
    assert r.caught and r.delay_min == 7 and r.called == "botnet" and r.max_sev == "critical" and r.early


def test_incident_after_grace_window_is_a_miss():
    events = pd.DataFrame([ev("2026-11-02T12:41:00")])           # end + 11 minutes
    assert not score_episodes(events, EPISODES).iloc[0].caught


def test_false_incidents_per_router_day():
    ts = pd.date_range("2026-11-02T00:00", periods=2 * 1440, freq="min").strftime("%Y-%m-%dT%H:%M:%S")
    feats = pd.DataFrame({"router_id": "R-001", "ts": ts})
    events = pd.DataFrame([ev("2026-11-02T12:05:00"),                                 # inside the episode
                           ev("2026-11-03T03:00:00", t="unknown_anomaly", sev="medium", inc="INC-0002")])
    fi = false_incidents(events, EPISODES, feats)
    normal_minutes = 2 * 1440 - C.MIN_HISTORY_MINUTES - 41                           # minus the 31+10 episode window
    assert fi["false_incidents"] == 1 and fi["by_type"] == {"unknown_anomaly": 1}
    assert abs(fi["normal_router_days"] - round(normal_minutes / 1440, 2)) < 1e-9


def test_evaluate_set_on_fake_data():
    from detection.detector import score_rows
    from detection.features import build_features
    from detection.train import split_routers, train_models
    from detection.evaluate import evaluate_set
    from tests.fake_data import fake_dataset

    recs, labs = fake_dataset(n_routers=12)
    feats = build_features(recs)
    tr, va, te = split_routers(feats.router_id.unique())
    bundle = train_models(feats, labs, tr, va)
    # Build an episodes table from the fake labels, in Person 1's format.
    l = labs[labs.label != "normal"]
    eps = (l.groupby(["router_id", "scenario", "label"])["ts"].agg(["min", "max"]).reset_index()
           .rename(columns={"min": "start_ts", "max": "end_ts"}))
    eps["loud_start_ts"] = ""
    res = evaluate_set(score_rows, bundle, recs[recs.router_id.isin(te)], eps[eps.router_id.isin(te)])
    assert res["routers"] == 2 and res["attack_episodes"] == 4
    assert res["attack_recall"] == 1.0 and res["correct_type_rate"] == 1.0
    assert res["botnet_early_rate"] is None                       # no loud phases in fake data
    assert set(res["by_scenario"]) == {"botnet_quiet_only", "brute_force_fast"}


def test_evaluate_all_report_is_json_with_flat_headline():
    import json
    from detection.features import build_features
    from detection.train import split_routers, train_models
    from detection.evaluate import evaluate_all, _json_default
    from tests.fake_data import fake_dataset

    recs, labs = fake_dataset(n_routers=12)
    tr, va, te = split_routers(recs.router_id.unique())
    bundle = train_models(build_features(recs), labs, tr, va)
    l = labs[labs.label != "normal"]
    eps = (l.groupby(["router_id", "scenario", "label"])["ts"].agg(["min", "max"]).reset_index()
           .rename(columns={"min": "start_ts", "max": "end_ts"}))
    eps["loud_start_ts"] = ""
    keep = lambda df: df[df.router_id.isin(te)]
    report = evaluate_all(bundle, {"fake_test": (keep(recs), keep(labs), keep(eps))})
    text = json.dumps(report, default=_json_default)               # must be valid JSON
    assert json.loads(text)["sets"]["fake_test"]["minute"]["rf_classes"]
    assert all(isinstance(v, float) for v in report["headline"].values())   # ready for mlflow.log_metrics
    assert "fake_test_models_attack_recall" in report["headline"]
    assert "fake_test_rules_attack_recall" in report["headline"]


def test_score_episodes_accepts_nan_from_default_read_csv():
    import numpy as np
    eps = EPISODES.copy()
    eps["loud_start_ts"] = np.nan                       # what pd.read_csv() gives for an empty cell
    events = pd.DataFrame([ev("2026-11-02T12:07:00")])
    r = score_episodes(events, eps).iloc[0]
    assert r.caught and r.early is None
