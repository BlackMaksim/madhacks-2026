"""Visual checks for the simulator (blueprint P1.3 and P1.5).

    python -m simulator.plots --data data/fleetA --out data/plots

rhythm.png:   outbound_conns over 2 days for 3 households (daily rhythm visible)
episodes.png: one example episode of each attack type, with 2 hours of context
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from simulator.households import make_router

SIGNALS = {
    "brute_force": ["failed_logins_wan", "login_sources"],
    "botnet": ["dns_failures", "new_domains", "new_dest_ips", "unique_dest_ips"],
}


def rhythm_plot(records: pd.DataFrame, out: Path, seed: int) -> None:
    ids = sorted(records["router_id"].unique())
    picks, seen = [], set()
    for i, rid in enumerate(ids):  # three different household types
        h = make_router(seed, i, rid).household
        if h not in seen:
            picks.append((rid, h)); seen.add(h)
        if len(picks) == 3:
            break
    fig, ax = plt.subplots(figsize=(12, 4))
    for rid, h in picks:
        r = records[records["router_id"] == rid]
        s = r.set_index(pd.to_datetime(r["ts"]))["outbound_conns"].rolling(15).mean()
        ax.plot(s.index, s.values, label=f"{rid} ({h})", linewidth=1.2)
    ax.set_title("outbound_conns per minute (15-min average), 2 simulated days")
    ax.set_ylabel("connections / min")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "rhythm.png", dpi=110)
    plt.close(fig)


def episode_plot(records, labels, episodes, out: Path) -> None:
    wanted = ["brute_force_fast", "brute_force_slow", "botnet_scan", "botnet_ddos", "botnet_quiet_only"]
    rows = [episodes[episodes["scenario"] == s].iloc[0] for s in wanted if (episodes["scenario"] == s).any()]
    fig, axes = plt.subplots(len(rows), 1, figsize=(12, 3 * len(rows)), squeeze=False)
    for ax, ep in zip(axes[:, 0], rows):
        start, end = pd.Timestamp(ep["start_ts"]), pd.Timestamp(ep["end_ts"])
        r = records[records["router_id"] == ep["router_id"]].copy()
        r["t"] = pd.to_datetime(r["ts"])
        r = r[(r["t"] >= start - pd.Timedelta(hours=1)) & (r["t"] <= end + pd.Timedelta(hours=1))]
        for sig in SIGNALS[ep["label"]]:
            ax.plot(r["t"], r[sig], label=sig, linewidth=1)
        ax.axvspan(start, end, color="red", alpha=0.08, label="episode")
        if isinstance(ep["loud_start_ts"], str) and ep["loud_start_ts"]:
            ax.axvline(pd.Timestamp(ep["loud_start_ts"]), color="red", linestyle="--", label="loud starts")
            ax.set_yscale("symlog")
        ax.set_title(f"{ep['scenario']} on {ep['router_id']} (intensity {ep['intensity']})")
        ax.legend(loc="upper left", fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "episodes.png", dpi=100)
    plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/fleetA")
    ap.add_argument("--out", default="data/plots")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(argv)
    data, out = Path(a.data), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    records = pd.read_parquet(data / "records.parquet")
    labels = pd.read_parquet(data / "labels.parquet")
    episodes = pd.read_csv(data / "episodes.csv", keep_default_na=False)
    rhythm_plot(records, out, a.seed)
    episode_plot(records, labels, episodes, out)
    print(f"wrote {out / 'rhythm.png'} and {out / 'episodes.png'}")


if __name__ == "__main__":
    main()
