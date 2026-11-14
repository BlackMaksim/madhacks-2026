"""Rules baseline (blueprint Section 6G, task P1.11): "why not a simple rule?"

    brute_force  if failed_logins_wan_w10 >= 20
    botnet       if outbound_conns_w10 or unique_dest_ips_w10 is >= 3x its own baseline

Same interface and output columns as detector.score_rows(), so evaluate.py can run
it through the same IncidentManager logic. Report whatever it scores.

    from detection.features import build_features
    from detection.rules_baseline import score_rows
    scores = score_rows(None, build_features(records))
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from detection.detector import SCORE_COLS

BRUTE_FAILS_W10 = 20
BOTNET_TIMES_USUAL = 3.0
MODEL_VERSION = "rules_baseline"


def _times_usual(feats: pd.DataFrame, counter: str) -> np.ndarray:
    """observed / usual, recovered from lr10 = ln(1+observed) - ln(1+usual). NaN -> 0."""
    observed = feats[f"{counter}_w10"].to_numpy(dtype=float)
    lr = feats[f"{counter}_lr10"].to_numpy(dtype=float)
    usual = np.exp(np.log1p(observed) - lr) - 1.0
    with np.errstate(divide="ignore", invalid="ignore"):
        ratio = observed / np.maximum(usual, 1e-9)
    return np.nan_to_num(ratio, nan=0.0)


def flags(feats: pd.DataFrame) -> pd.DataFrame:
    """Boolean columns brute_force and botnet, one row per feature row."""
    brute = feats["failed_logins_wan_w10"].to_numpy(dtype=float) >= BRUTE_FAILS_W10
    botnet = ((_times_usual(feats, "outbound_conns") >= BOTNET_TIMES_USUAL)
              | (_times_usual(feats, "unique_dest_ips") >= BOTNET_TIMES_USUAL))
    return pd.DataFrame({"brute_force": brute, "botnet": botnet}, index=feats.index)


def score_rows(bundle, feats: pd.DataFrame) -> pd.DataFrame:
    """bundle is ignored (kept for the score_rows() signature)."""
    f = flags(feats)
    rows = []
    for rid, ts, bf, bn in zip(feats["router_id"], feats["ts"], f["brute_force"], f["botnet"]):
        cls = "brute_force" if bf else "botnet" if bn else "normal"
        hit = cls != "normal"
        probs = {k: float(k == cls) for k in ("normal", "benign_unusual", "brute_force", "botnet")}
        rows.append({
            "router_id": rid, "ts": ts,
            "anomaly_score": 1.0 if hit else 0.0, "anomaly_pct": 1.0 if hit else 0.0, "flagged": bool(hit),
            "p_normal": probs["normal"], "p_benign_unusual": probs["benign_unusual"],
            "p_brute_force": probs["brute_force"], "p_botnet": probs["botnet"],
            "predicted_class": cls, "class_conf": 1.0,
            "verdict": "known_attack" if hit else "normal",
        })
    return pd.DataFrame(rows, columns=SCORE_COLS)
