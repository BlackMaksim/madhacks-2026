"""Train the Isolation Forest and the Random Forest (blueprint Section 6).

Runs the same way in Databricks (imported by notebook 03) and on a laptop
(Plan B: `python -m detection.train ...`).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

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


def minutes_into_episode(df: pd.DataFrame) -> pd.Series:
    """0, 1, 2, ... counting minutes since each attack or look-alike episode began
    (a run of the same non-normal scenario on one router). Normal rows get -1."""
    s = df["scenario"].astype(str)
    new_run = (s != s.groupby(df["router_id"]).shift()) | (df["router_id"] != df["router_id"].shift())
    run_id = new_run.cumsum()
    count = df.groupby(run_id).cumcount()
    return count.where(s != "normal", -1)


def train_rf(train_df: pd.DataFrame, seed: int = 42, normal_keep: float = 0.3):
    """Model 2: learn to name the pattern (normal / benign_unusual / brute_force / botnet).

    - Drops each episode's first 3 minutes: the 10-minute window hasn't seen the
      pattern yet, so those labels are noise.
    - Keeps only 30% of pure normal rows, to train faster.
    - class_weight="balanced_subsample" makes rare classes count more inside every tree.
    """
    df = train_df.copy()
    df["target"] = make_target(df).values
    into = minutes_into_episode(df)
    pure_normal = df["scenario"] == "normal"
    keep_normal = pure_normal & (np.random.default_rng(seed).random(len(df)) < normal_keep)
    rows = df[keep_normal | (~pure_normal & (into >= 3))]

    rf = RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=5,
                                class_weight="balanced_subsample", n_jobs=-1, random_state=seed)
    rf.fit(rows[C.FEATURES_RF].to_numpy(dtype=float), rows["target"].to_numpy())
    info = {"rf_train_rows": len(rows), "rf_class_counts": rows["target"].value_counts().to_dict()}
    return rf, info


def train_models(feats: pd.DataFrame, labels: pd.DataFrame,
                 train_routers: list[str], val_routers: list[str],
                 version: str = "v1", seed: int = 42) -> dict:
    """Train both models and return the bundle: one dict saved as one .joblib file.

    The bundle holds everything the live engine needs to score a minute exactly
    the way training did: both models, the feature lists, the percentile
    quantiles, the thresholds, and the scikit-learn version it was built with.
    """
    import datetime
    import sklearn

    df = join_labels(feats, labels)
    train_df = df[df["router_id"].isin(train_routers)]
    val_df = df[df["router_id"].isin(val_routers)]

    iforest, quantiles, if_info = train_iforest(train_df, val_df, seed=seed)
    rf, rf_info = train_rf(train_df, seed=seed)

    return {
        "version": version,
        "trained_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "iforest": iforest,
        "rf": rf,
        "features_if": list(C.FEATURES_IF),
        "features_rf": list(C.FEATURES_RF),
        "classes": list(rf.classes_),
        "val_score_quantiles": quantiles,
        "thresholds": dict(C.THRESHOLDS),
        "params": {
            "if_n_estimators": 200, "if_max_samples": 256,
            "rf_n_estimators": 200, "rf_max_depth": 14, "rf_min_samples_leaf": 5,
            "seed": seed, "n_train_routers": len(train_routers), "n_val_routers": len(val_routers),
            **if_info, **{k: v for k, v in rf_info.items() if k != "rf_class_counts"},
        },
        "rf_class_counts": rf_info["rf_class_counts"],
        "split": {"train": list(train_routers), "val": list(val_routers)},
    }


def save_bundle(bundle: dict, path: str) -> None:
    import os
    import joblib
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    joblib.dump(bundle, path, compress=3)


def validation_summary(bundle: dict, feats: pd.DataFrame, labels: pd.DataFrame) -> dict:
    """Quick minute-level check on the validation routers (the full grading is evaluate.py)."""
    from sklearn.metrics import confusion_matrix
    from detection.detector import score_rows

    val = join_labels(feats[feats["router_id"].isin(bundle["split"]["val"])], labels)
    scores = score_rows(bundle, val)
    val = val.assign(target=make_target(val).values, flagged=scores["flagged"].values,
                     pred=scores["predicted_class"].values, verdict=scores["verdict"].values)
    pure = val["scenario"] == "normal"
    classes = [c for c in C.CLASSES if c in set(val["target"]) | set(val["pred"])]
    cm = confusion_matrix(val["target"], val["pred"], labels=classes)
    return {
        "if_flag_rate_val_normal": float(val.loc[pure, "flagged"].mean()),
        "flagged_by_scenario": val.groupby("scenario")["flagged"].mean().round(3).to_dict(),
        "verdict_by_scenario": pd.crosstab(val["scenario"], val["verdict"], normalize="index").round(3),
        "confusion": pd.DataFrame(cm, index=[f"true {c}" for c in classes], columns=[f"pred {c}" for c in classes]),
    }


def main(argv=None):
    """Plan B: train on a laptop.  python -m detection.train --data data/fleetA --out models/edgesentinel_v2.joblib"""
    import argparse
    import os
    import time

    from detection.features import build_features

    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("--data", required=True, help="folder with records.parquet and labels.parquet")
    ap.add_argument("--out", required=True, help="where to save the model bundle (.joblib)")
    ap.add_argument("--version", default=None, help="bundle version; default from the file name, e.g. v2")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    version = args.version or os.path.basename(args.out).rsplit("_", 1)[-1].split(".")[0]

    t0 = time.perf_counter()
    records = pd.read_parquet(os.path.join(args.data, "records.parquet"))
    labels = pd.read_parquet(os.path.join(args.data, "labels.parquet"))
    feats = build_features(records)
    train_r, val_r, test_r = split_routers(feats["router_id"].unique(), seed=args.seed)
    print(f"{len(records):,} records, {feats['router_id'].nunique()} routers "
          f"-> train {len(train_r)} / val {len(val_r)} / test {len(test_r)}  ({time.perf_counter() - t0:.1f}s)")

    bundle = train_models(feats, labels, train_r, val_r, version=version, seed=args.seed)
    bundle["split"]["test"] = test_r
    save_bundle(bundle, args.out)
    print(f"saved {args.out} ({os.path.getsize(args.out) / 1e6:.1f} MB), version {version}, "
          f"classes {bundle['classes']}  ({time.perf_counter() - t0:.1f}s)")

    s = validation_summary(bundle, feats, labels)
    print(f"\nIsolation Forest flag rate on validation normal minutes: {s['if_flag_rate_val_normal']:.2%} "
          f"(target 0.2%-1%)")
    print("\nVerdicts on validation routers, share of minutes per scenario:")
    print(s["verdict_by_scenario"].to_string())
    print("\nRandom Forest on validation routers, every minute (rows = truth):")
    print(s["confusion"].to_string())


if __name__ == "__main__":
    main()
