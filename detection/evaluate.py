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


def evaluate_set(scorer, bundle, records: pd.DataFrame, episodes: pd.DataFrame) -> dict:
    """Grade one detector (our models, or the rules baseline) on one set of routers.

    scorer(bundle, feats) -> score rows, e.g. detection.detector.score_rows or
    detection.rules_baseline.score_rows. Both go through the same incident logic.
    """
    from detection.features import build_features

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
