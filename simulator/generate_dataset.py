"""Offline datasets for training and evaluation (blueprint Section 4).

    python -m simulator.generate_dataset --fleet A --seed 1 --routers 60 --days 2 --out data/fleetA
    python -m simulator.generate_dataset --fleet B --seed 2 --routers 30 --days 2 --out data/fleetB

Writes three files, kept apart:
    records.parquet  the records only, exactly the Section 9 format. No labels.
    labels.parquet   router_id, ts, label, scenario, phase, episode_id
    episodes.csv     one row per episode (attacks and look-alikes)

--version v0 = normal only, v1 = + both attacks, v2 = + look-alikes (default).
Data is synthetic and deliberately attack-heavy so the test set has enough episodes.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from simulator.fleet import LABEL_FIELDS, RECORD_FIELDS, TS_FMT, RouterSim
from simulator.scenarios import Botnet, BruteForce, ForgotPassword, NewDevice

FLEET_ID_START = {"A": 1, "B": 201, "LIVE": 101}
DEFAULT_START = "2026-11-02T00:00:00"
GAP = 120             # minutes between episodes on the same router
EARLIEST = 12 * 60    # no episode before hour 12: baselines need history first
EPISODE_COLS = ["episode_id", "router_id", "scenario", "label", "start_ts", "end_ts",
                "loud_start_ts", "intensity", "success"]


def schedule(fleet: str, router_id: str, seed: int, index: int, n_minutes: int, version: str):
    """The router's episodes: non-overlapping, >= 2 h apart, starting after hour 12."""
    rng = np.random.default_rng([seed, index, 3])
    wanted = []
    if version in ("v1", "v2"):
        if rng.random() < 0.8:
            wanted.append(Botnet)
        if rng.random() < 0.8:
            wanted.append(BruteForce)
    if version == "v2":
        wanted += [ForgotPassword] * int(rng.integers(1, 3))
        if rng.random() < 0.7:
            wanted.append(NewDevice)
    order = rng.permutation(len(wanted))

    episodes, taken = [], []  # taken: (start, end) intervals incl. the gap
    for k, j in enumerate(order, start=1):
        cls = wanted[j]
        ep = cls(f"{fleet}-{router_id}-E{k}", 0, np.random.default_rng([seed, index, 4, k]))
        latest = n_minutes - ep.duration
        for _ in range(200):
            if latest < EARLIEST:
                break
            s = int(rng.integers(EARLIEST, latest + 1))
            e = s + ep.duration
            if all(e + GAP <= a or s >= b + GAP for a, b in taken):
                ep.start = s
                taken.append((s, e))
                episodes.append(ep)
                break
    return sorted(episodes, key=lambda e: e.start)


def generate(fleet="A", seed=1, routers=60, days=2, start_ts=DEFAULT_START, version="v2", id_start=None):
    """Returns (records, labels, episodes) DataFrames."""
    id_start = FLEET_ID_START.get(fleet, 1) if id_start is None else id_start
    start = datetime.strptime(start_ts, TS_FMT)
    n_minutes = days * 1440
    stamps = [start + timedelta(minutes=m) for m in range(n_minutes)]
    recs, labs, eps = [], [], []
    for i in range(routers):
        rid = f"R-{id_start + i:03d}"
        sim = RouterSim(seed, i, rid)
        episodes = schedule(fleet, rid, seed, i, n_minutes, version)
        queue = list(episodes)
        for m, ts in enumerate(stamps):
            while queue and m >= queue[0].start + queue[0].duration:
                queue.pop(0)
            ep = queue[0] if queue and queue[0].active(m) else None
            rec, lab = sim.minute_record(ts, ep)
            recs.append(rec)
            labs.append(lab)
        for ep in episodes:
            s = start + timedelta(minutes=ep.start)
            eps.append({
                "episode_id": ep.episode_id, "router_id": rid, "scenario": ep.scenario,
                "label": ep.label,
                "start_ts": s.strftime(TS_FMT),
                "end_ts": (s + timedelta(minutes=ep.duration - 1)).strftime(TS_FMT),
                "loud_start_ts": (s + timedelta(minutes=ep.loud_start)).strftime(TS_FMT)
                                 if ep.loud_start is not None else "",
                "intensity": round(ep.intensity, 3),
                "success": "" if ep.success is None else str(ep.success).lower(),
            })
    records = pd.DataFrame(recs, columns=RECORD_FIELDS)
    labels = pd.DataFrame(labs, columns=LABEL_FIELDS)
    episodes = pd.DataFrame(eps, columns=EPISODE_COLS)
    return records, labels, episodes


def write(records, labels, episodes, out: str | Path) -> Path:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    records.to_parquet(out / "records.parquet", index=False)
    labels.to_parquet(out / "labels.parquet", index=False)
    episodes.to_csv(out / "episodes.csv", index=False)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fleet", default="A", help="A, B or LIVE (sets the first router ID)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--routers", type=int, default=60)
    ap.add_argument("--days", type=int, default=2)
    ap.add_argument("--start", default=DEFAULT_START)
    ap.add_argument("--version", default="v2", choices=["v0", "v1", "v2"])
    ap.add_argument("--id-start", type=int, default=None)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    t0 = time.time()
    records, labels, episodes = generate(a.fleet, a.seed, a.routers, a.days, a.start, a.version, a.id_start)
    out = write(records, labels, episodes, a.out)
    print(f"fleet {a.fleet} {a.version}: {len(records):,} records, {len(episodes)} episodes "
          f"-> {out} in {time.time() - t0:.1f}s")
    print(episodes["scenario"].value_counts().to_string() if len(episodes) else "(no episodes)")


if __name__ == "__main__":
    main()
