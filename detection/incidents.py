"""Turn minute-by-minute verdicts into one incident per router per problem.

Rules (blueprint Section 6F):
  open      >= 3 of the last 5 minutes suspicious, or 5 of 5 minutes `watch`
  one       at most one open incident per router
  type      most common type so far; a more serious type takes over once it has 3 minutes
  severity  botnet high (critical with the loud signature); brute_force medium
            (high after a success with >= 10 outside failures); unknown_anomaly medium;
            unusual_benign low
  escalate  type or severity goes up -> version + 1, report_needed (max version 3)
  close     20 calm minutes in a row -> resolved (a `watch` minute is not calm while
            an incident is open; this differs from the blueprint pseudocode on purpose)
  reopen    suspicious again within 30 minutes of closing -> same incident, version + 1
"""
from __future__ import annotations

from collections import Counter, deque
from datetime import datetime

from detection import config as C
from detection.features import evidence_for

TYPE_RANK = {t: i for i, t in enumerate(C.INCIDENT_TYPES)}
SEV_RANK = {s: i for i, s in enumerate(C.SEVERITIES)}

TREND_MINUTES = 30
TREND_BUCKET = 5
TREND_SIGNALS = {
    "botnet": ["dns_failures", "new_domains"],
    "brute_force": ["failed_logins_wan", "login_sources"],
}


def _minutes_between(a: str, b: str) -> float:
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60.0


def _minute_type(verdict: str, predicted_class: str) -> str | None:
    """Which incident type one minute votes for."""
    if verdict in ("known_attack", "watch"):
        return predicted_class if predicted_class in C.ATTACK_CLASSES else "unknown_anomaly"
    if verdict in ("unusual_benign", "unknown_anomaly"):
        return verdict
    return None


def _severity(inc_type: str, f: dict) -> str:
    if inc_type == "botnet":
        loud = (f.get("outbound_conns_lr10", 0) >= C.LOUD_LR10
                or f.get("unique_dest_ips_lr10", 0) >= C.LOUD_LR10)
        return "critical" if loud else "high"
    if inc_type == "brute_force":
        broke_in = (f.get("success_after_fails_w10", 0) >= 1
                    and f.get("failed_logins_wan_w10", 0) >= C.BRUTE_SUCCESS_MIN_FAILS)
        return "high" if broke_in else "medium"
    if inc_type == "unknown_anomaly":
        return "medium"
    return "low"


class IncidentManager:
    def __init__(self, open_k=C.INCIDENT_OPEN_K, window=C.INCIDENT_WINDOW,
                 close_after=C.INCIDENT_CLOSE_AFTER, reopen_within=C.INCIDENT_REOPEN_WITHIN,
                 max_version=C.INCIDENT_MAX_VERSION, next_id: int = 1):
        self.open_k, self.window = open_k, window
        self.close_after, self.reopen_within, self.max_version = close_after, reopen_within, max_version
        self._next_id = next_id
        self._history: dict[str, deque] = {}       # router -> last `window` (verdict, minute_type)
        self._raw: dict[str, deque] = {}           # router -> last 30 minutes of raw counters
        self._open: dict[str, dict] = {}           # router -> internal incident state
        self._closed: dict[str, dict] = {}         # router -> most recently closed incident

    # ------------------------------------------------------------------ public

    def update(self, score_row: dict, feature_row: dict) -> dict | None:
        """Returns {"event": "opened" | "escalated" | "updated" | "closed", "incident": {...}} or None."""
        rid, ts = score_row["router_id"], score_row["ts"]
        verdict, pclass = score_row["verdict"], score_row["predicted_class"]
        hist = self._history.setdefault(rid, deque(maxlen=self.window))
        hist.append((verdict, _minute_type(verdict, pclass)))
        self._raw.setdefault(rid, deque(maxlen=TREND_MINUTES)).append(
            {c: feature_row.get(c, 0) for c in C.COUNTERS_W10})
        suspicious = verdict in C.SUSPICIOUS_VERDICTS
        all_watch = len(hist) == self.window and all(v == "watch" for v, _ in hist)
        # While an incident is open, a `watch` minute (classifier >= 80% sure it's an
        # attack, Isolation Forest not flagged) also keeps it alive. Without this, an
        # incident opened by 5 watch minutes closed after 20 more watch minutes and a
        # new one opened: one password-guessing attack became 2-3 incidents.
        active = suspicious or verdict == "watch"

        inc = self._open.get(rid)
        if inc is None:
            closed = self._closed.get(rid)
            if ((suspicious or all_watch) and closed is not None
                    and _minutes_between(closed["closed_ts"], ts) <= self.reopen_within):
                return self._reopen(closed, score_row, feature_row)
            n_susp = sum(1 for v, _ in hist if v in C.SUSPICIOUS_VERDICTS)
            if n_susp >= self.open_k or all_watch:
                return self._create(rid, hist, score_row, feature_row)
            return None

        if active:
            inc["last_ts"] = ts
            inc["calm_streak"] = 0
            inc["verdict_counts"][verdict] += 1
            inc["type_counts"][_minute_type(verdict, pclass)] += 1
            inc["minutes_suspicious"] += 1
            new_type = self._pick_type(inc["type_counts"], inc["incident_type"])
            new_sev = _severity(new_type, feature_row)
            if SEV_RANK[new_sev] < SEV_RANK[inc["severity"]] and new_type == inc["incident_type"]:
                new_sev = inc["severity"]  # severity never goes down while open
            self._refresh(inc, score_row, feature_row)
            if (TYPE_RANK[new_type] > TYPE_RANK[inc["incident_type"]]
                    or SEV_RANK[new_sev] > SEV_RANK[inc["severity"]]):
                inc["incident_type"], inc["severity"] = new_type, new_sev
                self._bump_version(inc)
                return {"event": "escalated", "incident": self._public(inc)}
            return {"event": "updated", "incident": self._public(inc)}

        inc["calm_streak"] += 1
        if inc["calm_streak"] >= self.close_after:
            inc["status"], inc["closed_ts"] = "resolved", ts
            del self._open[rid]
            self._closed[rid] = inc
            return {"event": "closed", "incident": self._public(inc)}
        return None

    def open_incidents(self) -> list[dict]:
        return [self._public(i) for i in self._open.values()]

    def open_incident_for(self, router_id: str) -> dict | None:
        inc = self._open.get(router_id)
        return self._public(inc) if inc else None

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _pick_type(type_counts: Counter, current: str | None = None) -> str:
        counts = {t: n for t, n in type_counts.items() if t}
        most_common = max(counts, key=lambda t: (counts[t], TYPE_RANK[t]))
        serious = [t for t, n in counts.items() if n >= 3]
        best = max([most_common] + serious, key=TYPE_RANK.get)
        if current is not None and TYPE_RANK[current] > TYPE_RANK[best]:
            return current  # the type never goes down
        return best

    def _create(self, rid, hist, score_row, feature_row) -> dict:
        all_watch = all(v == "watch" for v, _ in hist)
        counted = [(v, t) for v, t in hist if all_watch or v in C.SUSPICIOUS_VERDICTS]
        type_counts = Counter(t for _, t in counted)
        inc_type = self._pick_type(type_counts)
        inc = {
            "incident_id": f"INC-{self._next_id:04d}", "router_id": rid, "status": "open",
            "opened_ts": score_row["ts"], "last_ts": score_row["ts"], "closed_ts": None,
            "version": 1, "incident_type": inc_type, "severity": _severity(inc_type, feature_row),
            "verdict_counts": Counter(v for v, _ in counted), "minutes_suspicious": len(counted),
            "detector": {}, "evidence": [], "trend_per_5_min": {}, "flags": {}, "login_summary": {},
            # internal only
            "type_counts": type_counts, "calm_streak": 0, "report_needed": True,
        }
        self._next_id += 1
        self._refresh(inc, score_row, feature_row)
        self._open[rid] = inc
        return {"event": "opened", "incident": self._public(inc)}

    def _reopen(self, inc, score_row, feature_row) -> dict:
        rid, verdict = score_row["router_id"], score_row["verdict"]
        del self._closed[rid]
        inc.update(status="open", closed_ts=None, last_ts=score_row["ts"], calm_streak=0)
        inc["verdict_counts"][verdict] += 1
        inc["type_counts"][_minute_type(verdict, score_row["predicted_class"])] += 1
        inc["minutes_suspicious"] += 1
        inc["incident_type"] = self._pick_type(inc["type_counts"], inc["incident_type"])
        new_sev = _severity(inc["incident_type"], feature_row)
        if SEV_RANK[new_sev] > SEV_RANK[inc["severity"]]:
            inc["severity"] = new_sev
        self._refresh(inc, score_row, feature_row)
        self._bump_version(inc)
        self._open[rid] = inc
        return {"event": "escalated", "incident": self._public(inc)}

    def _bump_version(self, inc) -> None:
        if inc["version"] < self.max_version:
            inc["version"] += 1
            inc["report_needed"] = True

    def _refresh(self, inc, score_row, f) -> None:
        """Update the detector snapshot, evidence, trend, flags and login summary."""
        inc["detector"] = {
            "anomaly_pct": score_row["anomaly_pct"],
            "anomaly_threshold": C.THRESHOLDS["anomaly_pct"],
            "predicted_class": score_row["predicted_class"],
            "class_probs": {c: score_row.get(f"p_{c}", 0.0) for c in C.CLASSES},
            "model_version": score_row.get("model_version", C.MODEL_VERSION),
        }
        ev = evidence_for(f)
        if ev:  # keep the last non-empty evidence list
            inc["evidence"] = ev
        signals = TREND_SIGNALS.get(inc["incident_type"]) or [e["signal"] for e in inc["evidence"][:2]] \
            or ["outbound_conns", "new_dest_ips"]
        raw = list(self._raw.get(inc["router_id"], []))
        inc["trend_per_5_min"] = {s: self._buckets(raw, s) for s in signals}
        inc["flags"] = {
            "new_device_last_60_min": bool(f.get("new_device_w60", 0) >= 1),
            "success_after_failed_logins": bool(f.get("success_after_fails_w10", 0) >= 1),
            "loud_phase_signature": bool(f.get("outbound_conns_lr10", 0) >= C.LOUD_LR10
                                         or f.get("unique_dest_ips_lr10", 0) >= C.LOUD_LR10),
        }
        inc["login_summary"] = {
            "failed_outside_logins_10min": int(f.get("failed_logins_wan_w10", 0)),
            # Sum of per-minute distinct sources: an upper bound on distinct sources in 10 min.
            "distinct_outside_sources_10min": int(f.get("login_sources_w10", 0)),
        }

    @staticmethod
    def _buckets(raw: list[dict], signal: str) -> list[int]:
        """Last 30 minutes as six 5-minute totals, oldest first (fewer if less history)."""
        vals = [int(r.get(signal, 0)) for r in raw]
        pad = (-len(vals)) % TREND_BUCKET
        vals = [0] * pad + vals
        return [sum(vals[i:i + TREND_BUCKET]) for i in range(0, len(vals), TREND_BUCKET)]

    @staticmethod
    def _public(inc: dict) -> dict:
        """The incident object in the Section 9 format (no internal fields)."""
        keys = ["incident_id", "router_id", "status", "opened_ts", "last_ts", "closed_ts", "version",
                "incident_type", "severity", "verdict_counts", "minutes_suspicious", "detector",
                "evidence", "trend_per_5_min", "flags", "login_summary"]
        out = {k: inc[k] for k in keys}
        out["verdict_counts"] = dict(inc["verdict_counts"])
        out["detector"] = dict(inc["detector"])
        out["evidence"] = [dict(e) for e in inc["evidence"]]
        out["trend_per_5_min"] = {k: list(v) for k, v in inc["trend_per_5_min"].items()}
        out["flags"] = dict(inc["flags"])
        out["login_summary"] = dict(inc["login_summary"])
        return out
