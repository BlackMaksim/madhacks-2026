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
