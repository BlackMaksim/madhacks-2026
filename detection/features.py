"""Feature builder shared by training (Databricks or laptop) and the live engine.

All feature groups from blueprint Section 6E. Every window looks backward only,
per router, sorted by time. The same function runs in Databricks and live.
Rows with less than ~7 hours of history have NaN baseline features; training
and evaluation drop them, and the live 24-hour warm-up fills them.
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

    # Shape ratios: what KIND of traffic, not how much. Dividing by at least 1 avoids 0/0.
    df["kb_per_conn_w10"] = df["kb_out_w10"] / np.maximum(df["outbound_conns_w10"], 1)          # tiny probes vs big transfers
    df["dns_fail_ratio_w10"] = df["dns_failures_w10"] / np.maximum(df["dns_queries_w10"], 1)    # failed lookups vs typos
    df["new_domain_ratio_w10"] = df["new_domains_w10"] / np.maximum(df["dns_queries_w10"], 1)
    df["wan_fail_share_w10"] = df["failed_logins_wan_w10"] / np.maximum(df["failed_logins_w10"], 1)  # outside vs inside

    # Event flags (0 or 1): context that changes what the numbers mean.
    df["success_after_fails_w10"] = ((df["successful_logins_w10"] >= 1)
                                     & (df["failed_logins_w10"] >= 3)).astype(int)
    df["new_device_w60"] = (df["new_devices_w60"] >= 1).astype(int)

    # Sudden jumps: change in "times usual" compared with 10 minutes earlier.
    g = df.groupby("router_id", sort=False)
    df["conns_jump"] = df["outbound_conns_lr10"] - g["outbound_conns_lr10"].shift(C.CHANGE_LAG)
    df["dest_jump"] = df["unique_dest_ips_lr10"] - g["unique_dest_ips_lr10"].shift(C.CHANGE_LAG)

    # Log versions for the Isolation Forest, so a few huge values don't dominate.
    df["log_failed_logins_wan_w60"] = np.log1p(df["failed_logins_wan_w60"])
    df["log_dns_failures_w60"] = np.log1p(df["dns_failures_w60"])
    df["log_new_devices_w60"] = np.log1p(df["new_devices_w60"])
    df["log_kb_per_conn_w10"] = np.log1p(df["kb_per_conn_w10"])

    # Time of day on a circle, so 23:59 and 00:00 are neighbours.
    t = pd.to_datetime(df["ts"])
    hour = t.dt.hour + t.dt.minute / 60.0
    df["hour_sin"] = np.sin(2 * math.pi * hour / 24.0)
    df["hour_cos"] = np.cos(2 * math.pi * hour / 24.0)

    missing = [c for c in C.FEATURES_ALL if c not in df.columns]
    assert not missing, f"build_features forgot: {missing}"
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
