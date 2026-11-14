import pandas as pd

from detection.train import make_target, split_routers

FLEET_A = [f"R-{i:03d}" for i in range(1, 61)]


def test_split_sizes_and_no_overlap():
    train, val, test = split_routers(FLEET_A)
    assert (len(train), len(val), len(test)) == (40, 10, 10)
    assert not set(train) & set(val) and not set(train) & set(test) and not set(val) & set(test)
    assert set(train) | set(val) | set(test) == set(FLEET_A)


def test_split_is_repeatable_and_order_free():
    assert split_routers(FLEET_A) == split_routers(list(reversed(FLEET_A)))
    assert split_routers(FLEET_A, seed=1) != split_routers(FLEET_A, seed=2)


def test_make_target_maps_lookalikes():
    labels = pd.DataFrame({
        "label":    ["normal", "normal", "normal", "brute_force", "botnet"],
        "scenario": ["normal", "benign_new_device", "benign_forgot_password", "brute_force_slow", "botnet_scan"],
    })
    assert make_target(labels).tolist() == ["normal", "benign_unusual", "benign_unusual", "brute_force", "botnet"]


def test_isolation_forest_flag_rate_and_attacks():
    import numpy as np
    from detection import config as C
    from detection.detector import anomaly_percentile
    from detection.features import build_features
    from detection.train import join_labels, train_iforest
    from tests.fake_data import fake_dataset

    recs, labs = fake_dataset(n_routers=12)
    df = join_labels(build_features(recs), labs)
    tr, va, te = split_routers(df.router_id.unique())
    iforest, q, _ = train_iforest(df[df.router_id.isin(tr)], df[df.router_id.isin(va)])
    assert len(q) == 2001 and np.all(np.diff(q) >= 0)

    def pct(rows):
        return anomaly_percentile(-iforest.score_samples(rows[C.FEATURES_IF].to_numpy(float)), q)

    val_normal = df[df.router_id.isin(va) & (df.scenario == "normal")]
    rate = (pct(val_normal) >= C.THRESHOLDS["anomaly_pct"]).mean()
    assert 0.002 <= rate <= 0.01, rate                     # blueprint: 0.2% to 1%
    p_all = pct(df)
    assert ((p_all >= 0) & (p_all <= 1)).all()
    attacks = df[df.router_id.isin(te) & (df.label != "normal")]
    assert np.median(pct(attacks)) > 0.99                  # attacks look unusual


def test_minutes_into_episode():
    from detection.train import minutes_into_episode
    df = pd.DataFrame({"router_id": ["A"] * 6 + ["B"] * 2,
                       "scenario": ["normal", "botnet_scan", "botnet_scan", "botnet_scan", "normal",
                                    "brute_force_fast", "brute_force_fast", "brute_force_fast"]})
    assert minutes_into_episode(df).tolist() == [-1, 0, 1, 2, -1, 0, 0, 1]


def test_random_forest_learns_the_attacks():
    import numpy as np
    from detection import config as C
    from detection.features import build_features
    from detection.train import join_labels, train_rf
    from tests.fake_data import fake_dataset

    recs, labs = fake_dataset(n_routers=12)
    df = join_labels(build_features(recs), labs)
    tr, va, _ = split_routers(df.router_id.unique())
    rf, info = train_rf(df[df.router_id.isin(tr)])
    assert set(rf.classes_) == {"normal", "brute_force", "botnet"}   # no look-alikes in fake data
    val = df[df.router_id.isin(va)]
    proba = rf.predict_proba(val[C.FEATURES_RF].to_numpy(float))
    assert np.allclose(proba.sum(axis=1), 1)
    pred = rf.predict(val[C.FEATURES_RF].to_numpy(float))
    for cls in ("brute_force", "botnet"):
        assert (pred[val.label.to_numpy() == cls] == cls).mean() > 0.8, cls
