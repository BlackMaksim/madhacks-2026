"""P1.11: the rules baseline returns score rows and flags fast brute force."""
import numpy as np

from detection.detector import SCORE_COLS
from detection.features import build_features
from detection.rules_baseline import score_rows
from simulator.fleet import RouterSim
from simulator.scenarios import BruteForce
from datetime import datetime, timedelta

import pandas as pd


def _router_with_fast_brute_force():
    sim = RouterSim(seed=1, index=0, router_id="R-001")
    ep = BruteForce("T-E1", start=900, rng=np.random.default_rng(0), intensity=1.0,
                    variant="fast", duration=60, success=False)
    t0 = datetime(2026, 11, 2)
    recs, labs = zip(*(sim.minute_record(t0 + timedelta(minutes=m), ep) for m in range(1020)))
    return pd.DataFrame(recs), pd.DataFrame(labs)


def test_rules_flag_fast_brute_force():
    records, labels = _router_with_fast_brute_force()
    scores = score_rows(None, build_features(records))
    assert list(scores.columns) == SCORE_COLS
    s = scores.merge(labels, on=["router_id", "ts"])
    attack = s[s["episode_id"] == "T-E1"]
    assert (attack["predicted_class"] == "brute_force").sum() >= 30
    assert set(attack.loc[attack["flagged"], "verdict"]) == {"known_attack"}
    before = s[(s["episode_id"] == "") & (s["ts"] < "2026-11-02T15:00:00")]
    assert (before["predicted_class"] != "brute_force").all()
