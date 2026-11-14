"""Small fake datasets so detection code can be tested before Person 1's real data.

These are NOT the simulator: households are plain Poisson noise with different
sizes, and attacks are simple bumps. Real training uses Person 1's files.
"""
import numpy as np
import pandas as pd

RATES = {  # rough per-minute rates for a fake household
    "failed_logins": 0.03, "failed_logins_wan": 0.03, "successful_logins": 0.001, "login_sources": 0.03,
    "outbound_conns": 40, "unique_dest_ips": 15, "new_dest_ips": 0.5,
    "dns_queries": 30, "dns_failures": 0.3, "new_domains": 0.6,
    "kb_out": 500, "kb_in": 9000, "new_devices": 0.0005,
}


def fake_records(routers=("R-101", "R-102", "R-103"), minutes=1700, seed=0, start="2026-11-13T00:00:00"):
    """Normal traffic only. R-103 never has failed logins (for the floor test)."""
    rng = np.random.default_rng(seed)
    ts = pd.date_range(start, periods=minutes, freq="min").strftime("%Y-%m-%dT%H:%M:%S")
    frames = []
    for k, rid in enumerate(routers):
        size = 0.5 + k
        data = {c: rng.poisson(r * size, minutes) for c, r in RATES.items()}
        if rid == "R-103":
            data["failed_logins"] = np.zeros(minutes, int)
            data["failed_logins_wan"] = np.zeros(minutes, int)
        frames.append(pd.DataFrame({"router_id": rid, "ts": ts, **data}))
    return pd.concat(frames, ignore_index=True)


def fake_dataset(n_routers=18, days=2, seed=0, start="2026-11-02T00:00:00"):
    """Records plus labels, in Person 1's file formats.

    Every router gets one quiet-botnet episode (40 min) and one fast password-
    guessing episode (60 min), both after hour 12 and far apart.
    """
    rng = np.random.default_rng(seed)
    minutes = days * 1440
    ts = pd.date_range(start, periods=minutes, freq="min").strftime("%Y-%m-%dT%H:%M:%S")
    recs, labs = [], []
    for k in range(n_routers):
        rid = f"R-{k + 1:03d}"
        size = rng.uniform(0.6, 3.0)
        d = {c: rng.poisson(r * size, minutes) for c, r in RATES.items()}
        label = np.array(["normal"] * minutes, dtype=object)
        scenario = label.copy()

        b0 = int(rng.integers(12 * 60, 30 * 60))           # botnet, quiet phase only
        b = slice(b0, b0 + 40)
        d["dns_failures"][b] += rng.poisson(4, 40)
        d["new_domains"][b] += rng.poisson(3, 40)
        d["new_dest_ips"][b] += rng.poisson(1, 40)
        d["outbound_conns"][b] += rng.poisson(3, 40)
        label[b], scenario[b] = "botnet", "botnet_quiet_only"

        f0 = (b0 + 6 * 60) % (minutes - 120)                # brute force, at least 6 h later
        f0 = max(f0, 12 * 60)
        f = slice(f0, f0 + 60)
        extra = rng.poisson(20, 60)
        d["failed_logins_wan"][f] += extra
        d["failed_logins"][f] += extra
        d["login_sources"][f] += 2
        label[f], scenario[f] = "brute_force", "brute_force_fast"

        recs.append(pd.DataFrame({"router_id": rid, "ts": ts, **d}))
        labs.append(pd.DataFrame({"router_id": rid, "ts": ts, "label": label, "scenario": scenario}))
    return pd.concat(recs, ignore_index=True), pd.concat(labs, ignore_index=True)
