"""Load the model bundle, score feature rows, apply the decision table.

Until a real bundle exists, load_bundle() returns a stub bundle: every router
scores `normal` except the routers listed in the STUB_ATTACK_ROUTERS env var
(comma-separated, default R-107), which score `known_attack` / botnet.
"""
from __future__ import annotations

import os
import warnings

import joblib
import numpy as np
import pandas as pd

from detection import config as C

SCORE_COLS = [
    "router_id", "ts", "anomaly_score", "anomaly_pct", "flagged",
    "p_normal", "p_benign_unusual", "p_brute_force", "p_botnet",
    "predicted_class", "class_conf", "verdict",
]


def load_bundle(path: str | None) -> dict:
    """Load a joblib model bundle. Missing file or path 'stub' -> stub bundle."""
    if not path or path == "stub" or not os.path.exists(path):
        if path and path != "stub":
            warnings.warn(f"Model file {path!r} not found; using the STUB detector.")
        return {"version": "stub", "thresholds": dict(C.THRESHOLDS)}
    bundle = joblib.load(path)
    try:
        import sklearn
        built = bundle.get("sklearn_version")
        if built and built != sklearn.__version__:
            warnings.warn(
                f"Model bundle was built with scikit-learn {built} but this laptop has "
                f"{sklearn.__version__}. Install the matching version or retrain locally (Plan B)."
            )
    except ImportError:
        pass
    return bundle


def minute_verdict(flagged: bool, predicted_class: str, class_conf: float, th: dict) -> str:
    """The decision table (blueprint Section 6D)."""
    if flagged:
        if predicted_class in C.ATTACK_CLASSES and class_conf >= th["class_conf"]:
            return "known_attack"
        if predicted_class == "benign_unusual" and class_conf >= th["class_conf"]:
            return "unusual_benign"
        return "unknown_anomaly"
    if predicted_class in C.ATTACK_CLASSES and class_conf >= th["watch_conf"]:
        return "watch"
    return "normal"


def anomaly_percentile(scores: np.ndarray, quantiles: np.ndarray) -> np.ndarray:
    """Share of validation-normal scores below each score, from stored quantiles."""
    idx = np.searchsorted(quantiles, scores, side="left")
    return np.clip(idx / (len(quantiles) - 1), 0.0, 1.0)


def _stub_scores(feats: pd.DataFrame, th: dict) -> pd.DataFrame:
    attack = {r.strip() for r in os.getenv("STUB_ATTACK_ROUTERS", "R-107").split(",") if r.strip()}
    rows = []
    for rid, ts in zip(feats["router_id"], feats["ts"]):
        if rid in attack:
            probs = {"normal": 0.05, "benign_unusual": 0.10, "brute_force": 0.04, "botnet": 0.81}
            score, pct = 0.612, 0.998
        else:
            probs = {"normal": 0.94, "benign_unusual": 0.03, "brute_force": 0.01, "botnet": 0.02}
            score, pct = 0.420, 0.500
        rows.append(_row(rid, ts, score, pct, probs, th))
    return pd.DataFrame(rows, columns=SCORE_COLS)


def _row(rid, ts, score, pct, probs, th) -> dict:
    flagged = bool(pct >= th["anomaly_pct"])
    top = max(probs, key=probs.get)
    conf = float(probs[top])
    return {
        "router_id": rid, "ts": ts,
        "anomaly_score": round(float(score), 4), "anomaly_pct": round(float(pct), 4), "flagged": flagged,
        "p_normal": round(float(probs.get("normal", 0.0)), 4),
        "p_benign_unusual": round(float(probs.get("benign_unusual", 0.0)), 4),
        "p_brute_force": round(float(probs.get("brute_force", 0.0)), 4),
        "p_botnet": round(float(probs.get("botnet", 0.0)), 4),
        "predicted_class": top, "class_conf": round(conf, 4),
        "verdict": minute_verdict(flagged, top, conf, th),
    }


def score_rows(bundle: dict, feats: pd.DataFrame) -> pd.DataFrame:
    """One score row per feature row (blueprint Section 9, interface 4)."""
    th = bundle.get("thresholds", C.THRESHOLDS)
    if bundle.get("version") == "stub":
        return _stub_scores(feats, th)

    X_if = feats[bundle["features_if"]].to_numpy(dtype=float)
    X_rf = feats[bundle["features_rf"]].to_numpy(dtype=float)
    scores = -bundle["iforest"].score_samples(X_if)
    pcts = anomaly_percentile(scores, np.asarray(bundle["val_score_quantiles"]))
    proba = bundle["rf"].predict_proba(X_rf)
    classes = list(bundle["classes"])

    rows = []
    for i, (rid, ts) in enumerate(zip(feats["router_id"], feats["ts"])):
        probs = {k: 0.0 for k in C.CLASSES}
        probs.update({c: float(p) for c, p in zip(classes, proba[i])})
        rows.append(_row(rid, ts, scores[i], pcts[i], probs, th))
    return pd.DataFrame(rows, columns=SCORE_COLS)
