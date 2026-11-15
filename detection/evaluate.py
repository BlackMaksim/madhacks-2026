"""Grade the detector the way an analyst would experience it (blueprint Section 6G).

The headline numbers are at the INCIDENT level: was each attack caught, how fast,
was it named correctly, and how many false incidents does an analyst get per
router-day. Labels are read only here, never by the detection code.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from detection import config as C
from detection.incidents import IncidentManager

DETECTION_GRACE_MIN = 10   # an incident counts if it opens up to 10 minutes after the episode ends


def replay_incidents(scores: pd.DataFrame, feats: pd.DataFrame) -> pd.DataFrame:
    """Feed every scored minute, in time order, through a fresh IncidentManager,
    exactly as the live engine would. Returns one row per incident event:
    router_id, ts, event (opened / escalated / updated / closed), incident_id,
    incident_type, severity."""
    s = scores.sort_values(["ts", "router_id"], kind="stable")
    f = feats.set_index(["router_id", "ts"]).loc[list(zip(s["router_id"], s["ts"]))].reset_index()
    mgr = IncidentManager()
    events = []
    for srow, frow in zip(s.to_dict("records"), f.to_dict("records")):
        ev = mgr.update(srow, frow)
        if ev:
            inc = ev["incident"]
            events.append({"router_id": inc["router_id"], "ts": srow["ts"], "event": ev["event"],
                           "incident_id": inc["incident_id"], "incident_type": inc["incident_type"],
                           "severity": inc["severity"]})
    return pd.DataFrame(events, columns=["router_id", "ts", "event", "incident_id", "incident_type", "severity"])


def _plus(ts: str, minutes: int) -> str:
    return (datetime.fromisoformat(ts) + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _minutes(a: str, b: str) -> float:
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60.0


def score_episodes(events: pd.DataFrame, episodes: pd.DataFrame) -> pd.DataFrame:
    """One row per episode: was it caught, how fast, what was it called.

    caught      an incident opened (or reopened) between the episode's start and
                10 minutes after its end
    delay_min   minutes from the episode start to that moment
    called      the incident's type at the end of the episode window
    max_sev     the highest severity it reached in that window
    early       botnet with a loud phase: caught before the loud phase began
    """
    rows = []
    for ep in episodes.to_dict("records"):
        start, stop = ep["start_ts"], _plus(ep["end_ts"], DETECTION_GRACE_MIN)
        ev = events[(events["router_id"] == ep["router_id"]) & (events["ts"] >= start) & (events["ts"] <= stop)]
        opens = ev[ev["event"].isin(["opened", "escalated"])]
        caught = len(opens) > 0
        row = {**ep, "caught": caught, "delay_min": None, "called": None, "max_sev": None, "early": None}
        if caught:
            row["delay_min"] = _minutes(start, opens["ts"].iloc[0])
            row["called"] = ev["incident_type"].iloc[-1]
            row["max_sev"] = max(ev["severity"], key=C.SEVERITIES.index)
            if ep.get("loud_start_ts"):
                row["early"] = opens["ts"].iloc[0] < ep["loud_start_ts"]
        rows.append(row)
    return pd.DataFrame(rows)


def _in_any_episode(router_id: str, ts: str, episodes: pd.DataFrame) -> bool:
    e = episodes[episodes["router_id"] == router_id]
    ends = e["end_ts"].map(lambda t: _plus(t, DETECTION_GRACE_MIN))
    return bool(((e["start_ts"] <= ts) & (ts <= ends)).any())


def false_incidents(events: pd.DataFrame, episodes: pd.DataFrame, feats: pd.DataFrame) -> dict:
    """Incidents that opened while nothing was happening, per router-day of normal time.

    "Normal time" = minutes after each router's warm-up that are not inside any
    attack or look-alike episode (start to end + 10 min). This number doesn't
    depend on how often attacks happen, so it is the analyst's real cost.
    """
    opened = events[events["event"] == "opened"]
    false = opened[[not _in_any_episode(r, t, episodes) for r, t in zip(opened["router_id"], opened["ts"])]]

    f = feats[["router_id", "ts"]].sort_values(["router_id", "ts"])
    warm = f[f.groupby("router_id").cumcount() >= C.MIN_HISTORY_MINUTES]
    in_ep = pd.Series(False, index=warm.index)
    for ep in episodes.to_dict("records"):
        stop = _plus(ep["end_ts"], DETECTION_GRACE_MIN)
        in_ep |= (warm["router_id"] == ep["router_id"]) & (warm["ts"] >= ep["start_ts"]) & (warm["ts"] <= stop)
    router_days = float((~in_ep).sum()) / 1440.0
    return {
        "false_incidents": int(len(false)),
        "normal_router_days": round(router_days, 2),
        "false_per_router_day": round(len(false) / router_days, 3) if router_days else None,
        "by_type": false["incident_type"].value_counts().to_dict(),
        "list": false[["router_id", "ts", "incident_type", "severity"]].to_dict("records"),
    }


def evaluate_set(scorer, bundle, records: pd.DataFrame, episodes: pd.DataFrame, feats: pd.DataFrame | None = None) -> dict:
    """Grade one detector (our models, or the rules baseline) on one set of routers.

    scorer(bundle, feats) -> score rows, e.g. detection.detector.score_rows or
    detection.rules_baseline.score_rows. Both go through the same incident logic.
    """
    from detection.features import build_features

    if feats is None:
        feats = build_features(records)
    events = replay_incidents(scorer(bundle, feats), feats)
    eps = score_episodes(events, episodes)
    attacks = eps[eps["label"] != "normal"]
    lookalikes = eps[eps["label"] == "normal"]
    loud = eps[eps["loud_start_ts"].astype(str) != ""]

    def outcome(r):
        if not r["caught"]:
            return "no_incident"
        if r["called"] == "unusual_benign":
            return "advisory"
        if r["called"] in C.ATTACK_CLASSES:
            return "mistaken_for_attack"
        return "unknown_anomaly"

    by_scenario = {}
    for scen, g in eps.groupby("scenario"):
        d = {"episodes": int(len(g)), "caught": int(g["caught"].sum())}
        if g["label"].iloc[0] != "normal":
            caught = g[g["caught"]]
            d["recall"] = round(d["caught"] / d["episodes"], 3)
            d["correct_type"] = int((caught["called"] == caught["label"]).sum())
            d["median_delay_min"] = float(caught["delay_min"].median()) if len(caught) else None
            d["p90_delay_min"] = float(caught["delay_min"].quantile(0.9)) if len(caught) else None
        else:
            d["outcomes"] = g.apply(outcome, axis=1).value_counts().to_dict()
        by_scenario[scen] = d

    caught_attacks = attacks[attacks["caught"]]
    fi = false_incidents(events, episodes, feats)
    return {
        "routers": int(records["router_id"].nunique()),
        "attack_episodes": int(len(attacks)),
        "attack_recall": round(float(attacks["caught"].mean()), 3) if len(attacks) else None,
        "correct_type_rate": round(float((caught_attacks["called"] == caught_attacks["label"]).mean()), 3)
        if len(caught_attacks) else None,
        "median_delay_min": float(caught_attacks["delay_min"].median()) if len(caught_attacks) else None,
        "p90_delay_min": float(caught_attacks["delay_min"].quantile(0.9)) if len(caught_attacks) else None,
        "botnet_early_rate": round(float(loud["early"].eq(True).mean()), 3) if len(loud) else None,
        "false_per_router_day": fi["false_per_router_day"],
        "false_incidents": fi["false_incidents"],
        "normal_router_days": fi["normal_router_days"],
        "lookalike_outcomes": lookalikes.apply(outcome, axis=1).value_counts().to_dict() if len(lookalikes) else {},
        "by_scenario": by_scenario,
    }


def minute_metrics(bundle: dict, feats: pd.DataFrame, labels: pd.DataFrame) -> dict:
    """The standard ML view, one row per router-minute (after warm-up).

    - Random Forest: confusion matrix and precision / recall / F1 per class
      (minutes in each episode's first 3 minutes are left out, as in training)
    - Isolation Forest: flag rate on pure normal minutes, and the share of botnet
      minutes flagged in the quiet vs the loud phase
    """
    from sklearn.metrics import classification_report, confusion_matrix
    from detection.detector import score_rows
    from detection.train import join_labels, make_target, minutes_into_episode

    df = join_labels(feats, labels)
    if "phase" in labels:
        df = df.merge(labels[["router_id", "ts", "phase"]], on=["router_id", "ts"], how="left")
    s = score_rows(bundle, df)
    df = df.assign(target=make_target(df).values, pred=s["predicted_class"].values, flagged=s["flagged"].values)

    into = minutes_into_episode(df)
    rf_rows = df[(into == -1) | (into >= 3)]
    classes = [c for c in C.CLASSES if c in set(rf_rows["target"]) | set(rf_rows["pred"])]
    rep = classification_report(rf_rows["target"], rf_rows["pred"], labels=classes, output_dict=True, zero_division=0)
    pure = df["scenario"] == "normal"
    out = {
        "rf_classes": classes,
        "rf_confusion": confusion_matrix(rf_rows["target"], rf_rows["pred"], labels=classes).tolist(),
        "rf_per_class": {c: {k: round(float(rep[c][k]), 3) for k in ("precision", "recall", "f1-score", "support")}
                         for c in classes},
        "if_flag_rate_normal": round(float(df.loc[pure, "flagged"].mean()), 4),
        "if_recall_by_scenario": df[~pure].groupby("scenario")["flagged"].mean().round(3).to_dict(),
    }
    if "phase" in df:
        bot = df[df["label"] == "botnet"]
        out["if_recall_botnet_by_phase"] = bot.groupby("phase")["flagged"].mean().round(3).to_dict()
    return out


HEADLINE_KEYS = ["attack_recall", "correct_type_rate", "median_delay_min", "p90_delay_min",
                 "botnet_early_rate", "false_per_router_day"]
NOTE = ("Synthetic data; tested on routers and a fleet the models never saw. "
        "Not an estimate of real-world accuracy.")


def evaluate_all(bundle: dict, datasets: dict) -> dict:
    """Grade our models and the rules baseline on every dataset.

    datasets = {"fleetA_test": (records, labels, episodes), "fleetB": (...)}
    Returns the report written to models/eval_report.json. report["headline"] is a
    flat dict of numbers, ready for mlflow.log_metrics().
    """
    import datetime
    import sklearn
    from detection.detector import score_rows
    from detection.features import build_features
    from detection.rules_baseline import score_rows as rules_score_rows

    report = {"model_version": bundle.get("version"), "sklearn_version": sklearn.__version__,
              "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
              "note": NOTE, "thresholds": bundle.get("thresholds"), "headline": {}, "sets": {}}
    for name, (records, labels, episodes) in datasets.items():
        feats = build_features(records)
        models = evaluate_set(score_rows, bundle, records, episodes, feats=feats)
        rules = evaluate_set(rules_score_rows, bundle, records, episodes, feats=feats)
        report["sets"][name] = {"models": models, "rules": rules, "minute": minute_metrics(bundle, feats, labels)}
        for who, res in (("models", models), ("rules", rules)):
            for k in HEADLINE_KEYS:
                if res.get(k) is not None:
                    report["headline"][f"{name}_{who}_{k}"] = float(res[k])
    return report


def _json_default(o):
    return o.item() if hasattr(o, "item") else str(o)


def main(argv=None):
    """python -m detection.evaluate --model models/edgesentinel_v2.joblib --data data/fleetA data/fleetB --out models/eval_report.json"""
    import argparse
    import json
    import os
    from detection.detector import load_bundle

    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", nargs="+", required=True, help="dataset folders (records, labels, episodes)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    bundle = load_bundle(a.model)
    seen = set(bundle["split"]["train"]) | set(bundle["split"]["val"])

    datasets = {}
    for folder in a.data:
        r = pd.read_parquet(os.path.join(folder, "records.parquet"))
        l = pd.read_parquet(os.path.join(folder, "labels.parquet"))
        e = pd.read_csv(os.path.join(folder, "episodes.csv"), keep_default_na=False)
        name = os.path.basename(os.path.normpath(folder))
        if seen & set(r["router_id"]):              # the training fleet: grade test routers only
            keep = set(bundle["split"]["test"])
            r, l, e = r[r.router_id.isin(keep)], l[l.router_id.isin(keep)], e[e.router_id.isin(keep)]
            name += "_test"
        datasets[name] = (r, l, e)

    report = evaluate_all(bundle, datasets)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(report, f, indent=2, default=_json_default)

    rows = []
    for name, s in report["sets"].items():
        for who in ("models", "rules"):
            r = s[who]
            rows.append({"set": name, "detector": who, "routers": r["routers"], "attacks": r["attack_episodes"],
                         **{k: r[k] for k in HEADLINE_KEYS}})
    print(pd.DataFrame(rows).to_string(index=False))
    print(f"\nwrote {a.out}.  {NOTE}")


if __name__ == "__main__":
    main()
