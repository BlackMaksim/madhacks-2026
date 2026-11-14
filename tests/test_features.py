"""The four feature checks from blueprint Section 6 ("Tests to run")."""
import numpy as np
import pandas as pd
import pytest

from detection import config as C
from detection.features import build_features

RATES = {  # rough per-minute rates for a fake household
    "failed_logins": 0.03, "failed_logins_wan": 0.03, "successful_logins": 0.001, "login_sources": 0.03,
    "outbound_conns": 40, "unique_dest_ips": 15, "new_dest_ips": 0.5,
    "dns_queries": 30, "dns_failures": 0.3, "new_domains": 0.6,
    "kb_out": 500, "kb_in": 9000, "new_devices": 0.0005,
}


def fake_records(routers=("R-101", "R-102", "R-103"), minutes=1700, seed=0, start="2026-11-13T00:00:00"):
    rng = np.random.default_rng(seed)
    ts = pd.date_range(start, periods=minutes, freq="min").strftime("%Y-%m-%dT%H:%M:%S")
    frames = []
    for k, rid in enumerate(routers):
        size = 0.5 + k  # households of different sizes
        data = {c: rng.poisson(r * size, minutes) for c, r in RATES.items()}
        if rid == "R-103":
            data["failed_logins"] = np.zeros(minutes, int)      # never any failed logins
            data["failed_logins_wan"] = np.zeros(minutes, int)
        frames.append(pd.DataFrame({"router_id": rid, "ts": ts, **data}))
    return pd.concat(frames, ignore_index=True)


@pytest.fixture(scope="module")
def records():
    return fake_records()


@pytest.fixture(scope="module")
def feats(records):
    return build_features(records)


def _same(a: pd.DataFrame, b: pd.DataFrame):
    """Equal values, treating NaN == NaN as equal."""
    pd.testing.assert_frame_equal(a.reset_index(drop=True), b.reset_index(drop=True),
                                  check_exact=False, rtol=1e-9, atol=1e-9)


def test_no_future_leakage(records, feats):
    """Change every row after time t: the features at or before t must not change."""
    t = sorted(records["ts"].unique())[1200]
    changed = records.copy()
    later = changed["ts"] > t
    for c in RATES:
        changed.loc[later, c] = changed.loc[later, c] * 7 + 50
    after = build_features(changed)
    upto = feats["ts"] <= t
    _same(feats.loc[upto, C.FEATURES_ALL], after.loc[after["ts"] <= t, C.FEATURES_ALL])


def test_batch_equals_live(records, feats):
    """The engine only keeps the last LIVE_BUFFER_MINUTES per router. Its newest row
    must be identical to the newest row computed on the full history."""
    buffer = records.sort_values(["router_id", "ts"]).groupby("router_id").tail(C.LIVE_BUFFER_MINUTES)
    live = build_features(buffer).groupby("router_id").tail(1)
    batch = feats.groupby("router_id").tail(1)
    _same(batch[C.FEATURES_ALL], live[C.FEATURES_ALL])


def test_no_missing_values_after_warmup(feats):
    assert list(feats.columns[-len(C.FEATURES_ALL):]) == C.FEATURES_ALL
    minute = feats.groupby("router_id").cumcount()
    warm = feats.loc[minute >= C.MIN_HISTORY_MINUTES, C.FEATURES_ALL]
    assert len(warm) > 0
    bad = warm.columns[warm.isna().any()].tolist()
    assert not bad, f"NaN after warm-up in: {bad}"


def test_floors_keep_ratios_finite(feats):
    """R-103 never has failed logins, so its baseline is 0. The floor must keep lr10 finite."""
    r = feats[(feats["router_id"] == "R-103")].iloc[C.MIN_HISTORY_MINUTES:]
    vals = r["failed_logins_wan_lr10"].to_numpy()
    assert np.isfinite(vals).all()
    assert np.allclose(vals, np.log1p(0) - np.log1p(C.FLOORS["failed_logins_wan"]))
