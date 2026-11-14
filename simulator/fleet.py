"""STUB Fleet (P1.2): step() returns the example normal record for every router.

Same interface as the real live Fleet (blueprint Section 4), so the engine,
features and privacy code can integrate now. The real simulator replaces this.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta
from pathlib import Path

_EXAMPLE = Path(__file__).resolve().parent.parent / "contracts" / "examples" / "record_normal.json"
TS_FMT = "%Y-%m-%dT%H:%M:%S"


class Fleet:
    def __init__(self, n_routers=12, seed=7, start_ts="2026-11-14T18:00:00", id_start=101):
        self.n_routers, self.seed, self.id_start = n_routers, seed, id_start
        self.start = datetime.strptime(start_ts, TS_FMT)
        self.router_ids = [f"R-{id_start + i:03d}" for i in range(n_routers)]
        self._template = json.loads(_EXAMPLE.read_text(encoding="utf-8"))
        self.reset()

    def _records(self, ts):
        out = []
        for rid in self.router_ids:
            r = copy.deepcopy(self._template)
            r["router_id"], r["ts"] = rid, ts.strftime(TS_FMT)
            out.append(r)
        return out

    def warmup(self, hours=24):
        out = []
        for m in range(hours * 60, 0, -1):
            out += self._records(self.start - timedelta(minutes=m))
        return out

    def step(self):
        recs = self._records(self.now)
        self._last_ts = self.now
        self.now += timedelta(minutes=1)
        return recs

    def trigger(self, router_id, scenario, intensity=1.0):
        pass  # stub: scenarios arrive with the real simulator

    def current_truth(self):
        ts = self._last_ts.strftime(TS_FMT) if self._last_ts else self.start.strftime(TS_FMT)
        return [{"router_id": r, "ts": ts, "label": "normal", "scenario": "normal", "phase": "none"}
                for r in self.router_ids]

    def reset(self):
        self.now = self.start
        self._last_ts = None
