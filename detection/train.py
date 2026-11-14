"""Train the Isolation Forest and the Random Forest (blueprint Section 6).

Runs the same way in Databricks (imported by notebook 03) and on a laptop
(Plan B: `python -m detection.train ...`).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from detection import config as C


def split_routers(router_ids: list[str], seed: int = 42) -> tuple[list[str], list[str], list[str]]:
    """Split routers (not rows) into train / validation / test, about 4:1:1.

    For fleet A's 60 routers that is 40 / 10 / 10. The same seed always gives
    the same split, so every training run is graded on the same test routers.
    """
    ids = sorted(set(router_ids))               # sort first so input order doesn't matter
    rng = np.random.default_rng(seed)
    rng.shuffle(ids)
    n_val = round(len(ids) / 6)
    n_test = round(len(ids) / 6)
    val, test, train = ids[:n_val], ids[n_val:n_val + n_test], ids[n_val + n_test:]
    return sorted(train), sorted(val), sorted(test)


def make_target(labels: pd.DataFrame) -> pd.Series:
    """The class the Random Forest learns for each row.

    Person 1's `label` is normal / brute_force / botnet. The two harmless
    look-alikes (scenario benign_forgot_password, benign_new_device) are labeled
    `normal` by the simulator, but we teach the classifier to name them
    `benign_unusual`, so it can tell "harmless but odd" from plain normal.
    """
    target = labels["label"].astype(str).copy()
    benign = labels["scenario"].astype(str).str.startswith("benign_")
    target[benign] = "benign_unusual"
    unknown = set(target.unique()) - set(C.CLASSES)
    assert not unknown, f"Unexpected labels: {unknown}"
    return target.rename("target")


def join_labels(feats: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Attach label and scenario to each feature row, and drop each router's
    first MIN_HISTORY_MINUTES rows (no baseline yet, so their features are blank).

    Labels are only used for training and evaluation, never as model inputs.
    """
    df = feats.merge(labels[["router_id", "ts", "label", "scenario"]],
                     on=["router_id", "ts"], how="inner", validate="one_to_one")
    df = df.sort_values(["router_id", "ts"], kind="stable").reset_index(drop=True)
    minute = df.groupby("router_id").cumcount()
    return df[minute >= C.MIN_HISTORY_MINUTES].reset_index(drop=True)


def train_iforest(train_df: pd.DataFrame, val_df: pd.DataFrame, seed: int = 42):
    """Model 1: learn what normal looks like, from pure normal minutes only.

    Returns the fitted model and 2,001 quantiles of the anomaly scores of the
    VALIDATION routers' normal minutes. Those quantiles turn any score into
    "more unusual than X% of normal minutes from routers the model never saw".
    """
    normal_train = train_df[train_df["scenario"] == "normal"]
    normal_val = val_df[val_df["scenario"] == "normal"]
    X_train = normal_train[C.FEATURES_IF].to_numpy(dtype=float)
    X_val = normal_val[C.FEATURES_IF].to_numpy(dtype=float)
    assert np.isfinite(X_train).all() and np.isfinite(X_val).all(), "blank features: drop warm-up rows first"

    iforest = IsolationForest(n_estimators=200, max_samples=256, random_state=seed)
    iforest.fit(X_train)

    # scikit-learn's score is LOWER for more unusual rows; flip it so higher = more unusual.
    val_scores = -iforest.score_samples(X_val)
    quantiles = np.quantile(val_scores, np.linspace(0, 1, 2001))
    info = {"if_train_rows": len(X_train), "if_val_rows": len(X_val)}
    return iforest, quantiles, info
