"""Feature builder shared by training (Databricks or laptop) and the live engine.

STUB VERSION (E.2): computes the 10-minute totals and the time-of-day features
for real; every other feature is 0.0. The output columns are already final, so
the engine, Silver notebook and incident manager can be built against it.
The real version (E.3) replaces the zeros without changing the columns.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from detection import config as C

# Columns returned besides FEATURES_ALL. Raw counters are passed through so the
# incident manager can build per-5-minute trends.
ID_COLS = ["router_id", "ts"]


def build_features(records: pd.DataFrame) -> pd.DataFrame:
    """Records in the Section 9 format, any routers, any order.

    Returns router_id, ts, the raw per-minute counters and FEATURES_ALL for every
    input row, sorted by router_id then ts. Backward-looking only.
    """
    df = records[ID_COLS + C.COUNTERS_W10].copy()
    df = df.sort_values(ID_COLS, kind="stable").reset_index(drop=True)
    g = df.groupby("router_id", sort=False)

    # 10-minute totals: smooth out one-minute noise.
    for c in C.COUNTERS_W10:
        df[f"{c}_w10"] = g[c].transform(lambda s: s.rolling(C.WINDOW_SHORT, min_periods=1).sum())

    # 60-minute totals: slow attacks build up over an hour.
    for c in C.COUNTERS_W60:
        df[f"{c}_w60"] = g[c].transform(lambda s: s.rolling(C.WINDOW_LONG, min_periods=1).sum())

    # Compare each router with its own normal ("how many times usual").
    # usual = median of this router's 10-minute totals over the previous 24 hours,
    #         shifted back 60 minutes so a current attack can't raise its own baseline.
    # It stays empty (NaN) until 6 hours of history exist; those rows are dropped in training.
    for c in C.COUNTERS_LR10:
        usual = df.groupby("router_id", sort=False)[f"{c}_w10"].transform(
            lambda s: s.shift(C.BASELINE_SHIFT)
                       .rolling(C.BASELINE_WINDOW, min_periods=C.BASELINE_MIN_PERIODS)
                       .median())
        floored = np.maximum(usual, C.FLOORS[c])  # stays NaN where there is no baseline yet
        df[f"{c}_lr10"] = np.log1p(df[f"{c}_w10"]) - np.log1p(floored)

    hour = pd.to_datetime(df["ts"]).dt.hour + pd.to_datetime(df["ts"]).dt.minute / 60.0
    df["hour_sin"] = np.sin(2 * math.pi * hour / 24.0)
    df["hour_cos"] = np.cos(2 * math.pi * hour / 24.0)

    for col in C.FEATURES_ALL:
        if col not in df.columns:
            df[col] = 0.0

    return df[ID_COLS + C.COUNTERS_W10 + C.FEATURES_ALL]


def evidence_for(feature_row: dict, top_k: int = C.EVIDENCE_TOP_K) -> list[dict]:
    """Up to top_k signals that are at least ~2x this router's usual level.

    Each item: signal, window_min, observed (10-minute total), usual (the
    router's baseline, after the floor) and times_usual, highest first.
    Because lr10 = ln(1 + observed) - ln(1 + usual), usual and times_usual
    are recovered exactly from the feature row.
    """
    items = []
    for c in C.COUNTERS_LR10:
        lr = float(feature_row.get(f"{c}_lr10", 0.0) or 0.0)
        if not math.isfinite(lr) or lr < C.EVIDENCE_MIN_LR10:  # no baseline yet, or not unusual
            continue
        observed = float(feature_row.get(f"{c}_w10", 0.0) or 0.0)
        usual = math.exp(math.log1p(observed) - lr) - 1.0
        items.append({
            "signal": c,
            "window_min": C.WINDOW_SHORT,
            "observed": int(round(observed)),
            "usual": int(round(usual)),
            "times_usual": round(math.exp(lr), 1),
        })
    items.sort(key=lambda d: d["times_usual"], reverse=True)
    return items[:top_k]
