import math

import pandas as pd

from detection import config as C
from detection.detector import load_bundle, minute_verdict, score_rows, SCORE_COLS
from detection.features import build_features, evidence_for

TH = C.THRESHOLDS


# One test per row of the decision table (blueprint Section 6D).
def test_flagged_attack_is_known_attack():
    assert minute_verdict(True, "botnet", 0.81, TH) == "known_attack"
    assert minute_verdict(True, "brute_force", 0.60, TH) == "known_attack"


def test_flagged_benign_is_unusual_benign():
    assert minute_verdict(True, "benign_unusual", 0.7, TH) == "unusual_benign"


def test_flagged_normal_or_unsure_is_unknown_anomaly():
    assert minute_verdict(True, "normal", 0.9, TH) == "unknown_anomaly"
    assert minute_verdict(True, "botnet", 0.55, TH) == "unknown_anomaly"


def test_not_flagged_confident_attack_is_watch():
    assert minute_verdict(False, "botnet", 0.85, TH) == "watch"
    assert minute_verdict(False, "brute_force", 0.79, TH) == "normal"


def test_not_flagged_anything_else_is_normal():
    assert minute_verdict(False, "normal", 0.99, TH) == "normal"
    assert minute_verdict(False, "benign_unusual", 0.99, TH) == "normal"


def test_evidence_recovers_usual_and_ratio():
    row = {"dns_failures_w10": 41, "dns_failures_lr10": math.log(42) - math.log(4),
           "kb_out_w10": 500, "kb_out_lr10": 0.1}
    ev = evidence_for(row)
    assert ev == [{"signal": "dns_failures", "window_min": 10, "observed": 41, "usual": 3, "times_usual": 10.5}]


def _records(routers, minutes, start="2026-11-14T18:00:00"):
    ts = pd.date_range(start, periods=minutes, freq="min").strftime("%Y-%m-%dT%H:%M:%S")
    rows = [{"router_id": r, "ts": t, **{c: 1 for c in C.COUNTERS_W10}} for r in routers for t in ts]
    return pd.DataFrame(rows)


def test_feature_columns_and_stub_scores():
    feats = build_features(_records(["R-101", "R-107"], 30))
    assert set(C.FEATURES_ALL) <= set(feats.columns)
    assert len(C.FEATURES_IF) == 18
    assert feats.groupby("router_id")["outbound_conns_w10"].max().eq(10).all()
    scores = score_rows(load_bundle("stub"), feats.groupby("router_id").tail(1))
    assert list(scores.columns) == SCORE_COLS
    v = dict(zip(scores["router_id"], scores["verdict"]))
    assert v == {"R-101": "normal", "R-107": "known_attack"}
    probs = scores[["p_normal", "p_benign_unusual", "p_brute_force", "p_botnet"]].sum(axis=1)
    assert ((probs - 1).abs() < 1e-6).all()
    assert scores["anomaly_pct"].between(0, 1).all()
