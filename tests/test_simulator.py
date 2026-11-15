"""P1 simulator checks (blueprint Section 4 checklist + Section 9 record contract)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest
from pydantic import BaseModel, ConfigDict

from simulator.fleet import RECORD_FIELDS, Fleet
from simulator.generate_dataset import generate, write
from simulator.households import INJECTION_DEVICE

try:  # P4 owns contracts/models.py; use it once it exists
    from contracts.models import Record
except ImportError:  # identical copy of the Section 9 model until then
    class Record(BaseModel):
        model_config = ConfigDict(extra="forbid")
        router_id: str; ts: str; customer_name: str; account_id: str; public_ip: str
        failed_logins: int; failed_logins_wan: int; successful_logins: int; login_sources: int
        outbound_conns: int; unique_dest_ips: int; new_dest_ips: int
        dns_queries: int; dns_failures: int; new_domains: int
        kb_out: int; kb_in: int; devices: int; new_devices: int
        login_src_ips: list[str]; usernames_tried: list[str]; dest_ips: list[str]
        domains: list[str]; device_names: list[str]

ROOT = Path(__file__).resolve().parent.parent
LIST_CAPS = {"login_src_ips": 10, "usernames_tried": 10, "dest_ips": 10, "domains": 10, "device_names": 30}
INT_FIELDS = [f for f in RECORD_FIELDS if f not in LIST_CAPS and f not in
              ("router_id", "ts", "customer_name", "account_id", "public_ip")]


@pytest.fixture(scope="module")
def small():
    return generate("A", seed=1, routers=8, days=2)


def _to_dict(row: pd.Series) -> dict:
    d = row.to_dict()
    for k in LIST_CAPS:
        d[k] = [str(x) for x in d[k]]
    for k in INT_FIELDS:
        d[k] = int(d[k])
    return d


@pytest.mark.parametrize("name", ["record_normal.json", "record_botnet_quiet.json"])
def test_example_records_validate(name):
    Record.model_validate_json((ROOT / "contracts" / "examples" / name).read_text(encoding="utf-8"))


def test_same_seed_identical_files(tmp_path):
    hashes = []
    for run in ("a", "b"):
        out = write(*generate("A", seed=1, routers=3, days=1), tmp_path / run)
        hashes.append({f: hashlib.sha256((out / f).read_bytes()).hexdigest()
                       for f in ("records.parquet", "labels.parquet", "episodes.csv")})
    assert hashes[0] == hashes[1]


def test_different_seed_differs():
    a, _, _ = generate("A", seed=1, routers=2, days=1)
    b, _, _ = generate("A", seed=2, routers=2, days=1)
    assert not a["outbound_conns"].equals(b["outbound_conns"])


def test_shape_and_no_missing(small):
    records, labels, episodes = small
    assert list(records.columns) == RECORD_FIELDS
    assert len(records) == len(labels) == 8 * 2 * 1440
    assert not records.isna().any().any()
    assert not labels[["router_id", "ts", "label", "scenario", "phase"]].isna().any().any()
    assert set(labels["label"]) <= {"normal", "brute_force", "botnet"}
    assert set(labels["phase"]) <= {"none", "quiet", "loud"}
    assert (records[["router_id", "ts"]].values == labels[["router_id", "ts"]].values).all()
    assert "label" not in records.columns


def test_counter_invariants_and_list_caps(small):
    r = small[0]
    assert (r["unique_dest_ips"] <= r["outbound_conns"]).all()
    assert (r["new_dest_ips"] <= r["unique_dest_ips"]).all()
    assert (r["failed_logins_wan"] <= r["failed_logins"]).all()
    assert (r[INT_FIELDS] >= 0).all().all()
    for col, cap in LIST_CAPS.items():
        assert r[col].map(len).max() <= cap, col


def test_episodes_match_labels(small):
    _, labels, episodes = small
    assert len(episodes) > 0
    for ep in episodes.itertuples():
        rows = labels[labels["episode_id"] == ep.episode_id]
        assert rows["ts"].min() == ep.start_ts and rows["ts"].max() == ep.end_ts
        assert (rows["router_id"] == ep.router_id).all()
        assert (rows["scenario"] == ep.scenario).all() and (rows["label"] == ep.label).all()
        assert rows["ts"].min() >= "2026-11-02T12:00:00"  # no episode before hour 12
        if ep.scenario in ("botnet_scan", "botnet_ddos"):
            assert rows.loc[rows["phase"] == "loud", "ts"].min() == ep.loud_start_ts
    # never overlapping, at least 2 hours apart
    for _, g in episodes.sort_values("start_ts").groupby("router_id"):
        s, e = pd.to_datetime(g["start_ts"]), pd.to_datetime(g["end_ts"])
        assert ((s.iloc[1:].values - e.iloc[:-1].values) >= pd.Timedelta(minutes=120)).all()
    normal = labels[labels["episode_id"] == ""]
    assert (normal["label"] == "normal").all() and (normal["scenario"] == "normal").all()


def test_1000_records_validate(small):
    for _, row in small[0].sample(1000, random_state=0).iterrows():
        Record.model_validate(_to_dict(row))


def test_daily_rhythm(small):
    r = small[0].copy()
    r["hour"] = pd.to_datetime(r["ts"]).dt.hour
    by_hour = r.groupby("hour")["outbound_conns"].mean()
    assert by_hour.loc[19] > 2 * by_hour.loc[3]  # evenings busier than nights fleet-wide


def test_attacks_show_up(small):
    records, labels, _ = small
    bf = labels["label"] == "brute_force"
    if bf.any():
        assert records.loc[bf, "failed_logins_wan"].mean() > 1.0
    quiet = labels["phase"] == "quiet"
    if quiet.any():
        assert records.loc[quiet, "dns_failures"].mean() > records.loc[~quiet, "dns_failures"].mean() + 1


def test_v0_is_normal_only():
    _, labels, episodes = generate("A", seed=1, routers=3, days=1, version="v0")
    assert len(episodes) == 0 and (labels["label"] == "normal").all()


def test_generation_speed():
    import time
    t0 = time.time()
    generate("A", seed=1, routers=10, days=1)
    assert (time.time() - t0) * 6 < 120  # 60 routers x 1 day under 2 minutes


# --- live mode ----------------------------------------------------------------------

def test_live_fleet_interface():
    f = Fleet()
    warm = f.warmup(hours=1)
    assert len(warm) == 60 * 12 and warm[-1]["ts"] == "2026-11-14T17:59:00"
    recs = f.step()
    assert [r["router_id"] for r in recs] == [f"R-{101 + i}" for i in range(12)]
    assert all(r["ts"] == "2026-11-14T18:00:00" for r in recs)
    for r in recs:
        Record.model_validate(r)
    truth = f.current_truth()
    assert len(truth) == 12 and all(t["label"] == "normal" for t in truth)
    assert set(truth[0]) == {"router_id", "ts", "label", "scenario", "phase"}


def test_live_is_repeatable():
    a, b = Fleet(), Fleet()
    a.warmup(hours=1); b.warmup(hours=1)
    for f in (a, b):
        f.trigger("R-107", "botnet")
    assert [a.step() for _ in range(5)] == [b.step() for _ in range(5)]


def test_live_botnet_quiet_then_loud():
    f = Fleet()
    f.warmup(hours=1)
    f.trigger("R-107", "botnet")
    phases, scenarios = [], []
    for _ in range(80):
        f.step()
        t = next(x for x in f.current_truth() if x["router_id"] == "R-107")
        phases.append(t["phase"])
        scenarios.append(t["scenario"])
    assert phases[:60] == ["quiet"] * 60          # quiet for 60 minutes by default
    assert set(scenarios[:60]) == {"botnet"}       # not "botnet_quiet_only": loud is still coming
    assert set(scenarios[60:75]) == {"botnet_scan"}
    assert phases[60:75] == ["loud"] * 15          # then a 15-minute scan
    assert phases[75:] == ["none"] * 5


def test_live_botnet_loud_button():
    f = Fleet()
    f.warmup(hours=1)
    f.trigger("R-107", "botnet")
    for _ in range(5):
        f.step()
    f.trigger("R-107", "botnet_loud")
    recs = f.step()
    t = next(x for x in f.current_truth() if x["router_id"] == "R-107")
    assert t["phase"] == "loud" and t["scenario"] == "botnet_scan"
    for _ in range(3):
        recs = f.step()
    r107 = next(r for r in recs if r["router_id"] == "R-107")
    assert r107["unique_dest_ips"] > 100


def test_live_triggers_and_reset():
    f = Fleet()
    f.warmup(hours=1)
    f.trigger("R-103", "brute_force_fast")
    f.trigger("R-102", "new_device")
    f.trigger("R-105", "forgot_password")
    fails, new_dev = 0, 0
    for _ in range(10):
        for r in f.step():
            if r["router_id"] == "R-103":
                fails += r["failed_logins_wan"]
            if r["router_id"] == "R-102":
                new_dev += r["new_devices"]
    assert fails > 50 and new_dev == 1
    f.reset()
    f.step()
    assert all(t["label"] == "normal" for t in f.current_truth())
    with pytest.raises(ValueError):
        f.trigger("R-999", "botnet")


def test_prompt_injection_device_on_r104():
    f = Fleet()
    recs = f.step()
    assert INJECTION_DEVICE in next(r for r in recs if r["router_id"] == "R-104")["device_names"]
    assert all(INJECTION_DEVICE not in r["device_names"] for r in recs if r["router_id"] != "R-104")
