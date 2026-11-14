"""The four feature checks from blueprint Section 6 ("Tests to run")."""
import numpy as np
import pandas as pd
import pytest

from detection import config as C
from detection.features import build_features
from tests.fake_data import RATES, fake_records


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
