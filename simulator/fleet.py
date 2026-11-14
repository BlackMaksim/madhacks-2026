"""Router fleet simulator: normal minutes and live demo mode (blueprint Section 4).

One record per router per simulated minute, in the Section 9 format (v1.1).
The same RouterSim makes the offline datasets (generate_dataset.py) and the live
12-router demo fleet (Fleet), so both produce identical-looking records.

Every number is a synthetic demonstration parameter, not a real-world measurement.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np

from simulator.households import MAX_DEVICE_NAMES, MAX_LIST, USERNAMES, RouterProfile, make_router
from simulator.scenarios import (
    Botnet, BruteForce, Episode, ForgotPassword, NewDevice, label_row, rand_ip,
)

TS_FMT = "%Y-%m-%dT%H:%M:%S"

# Field order of the Section 9 record (v1.1).
RECORD_FIELDS = [
    "router_id", "ts", "customer_name", "account_id", "public_ip",
    "failed_logins", "failed_logins_wan", "successful_logins", "login_sources",
    "outbound_conns", "unique_dest_ips", "new_dest_ips",
    "dns_queries", "dns_failures", "new_domains",
    "kb_out", "kb_in", "devices", "new_devices",
    "login_src_ips", "usernames_tried", "dest_ips", "domains", "device_names",
]
LABEL_FIELDS = ["router_id", "ts", "label", "scenario", "phase", "episode_id"]

GUEST_PROB = 1.0 / 2880.0       # a guest phone joins about once every 2 days
BG_FAILED_WAN = 0.03            # background scanner noise, ~1 failed login per 30 min
OWNER_LOGIN = 0.0005            # owner logs in from inside the home
KB_SIGMA = 0.35


def _cyclic(pool: list[str], start: int, k: int) -> list[str]:
    n = len(pool)
    return [pool[(start + j) % n] for j in range(min(k, n))]


class RouterSim:
    """One router: its profile, its own random generator and its device state."""

    def __init__(self, seed: int, index: int, router_id: str):
        self.seed, self.index = seed, index
        self.profile: RouterProfile = make_router(seed, index, router_id)
        self.rng = np.random.default_rng([seed, index, 1])        # normal traffic
        self.base_devices = list(self.profile.device_names)
        self.extra_devices: list[str] = []                         # e.g. a new camera
        self.guest_until = -1
        self.minute = 0

    def reset_devices(self) -> None:
        self.extra_devices, self.guest_until = [], -1

    # --- one normal minute: steps 1-9 of Section 4 -------------------------------------
    def draft(self, ts: datetime) -> dict:
        p, rng = self.profile, self.rng
        burst = rng.lognormal(0.0, 0.3)                                  # 1. shared burst
        m = p.size * p.rhythm(ts.hour) * burst                            # 2. rate multiplier
        r = p.rates
        conns = int(rng.poisson(r["outbound_conns"] * m))                # 3.
        dests = min(conns, int(rng.poisson(r["unique_dest_ips"] * m)))
        new_dests = int(rng.binomial(dests, 0.03))                       # 4.
        dns = int(rng.poisson(r["dns_queries"] * m))                     # 5.
        new_dom = int(rng.binomial(dns, 0.02))
        dns_fail = int(rng.binomial(dns, 0.01))
        kb_out = int(round(r["kb_out"] * m * rng.lognormal(-KB_SIGMA ** 2 / 2, KB_SIGMA)))  # 6.
        kb_in = int(round(r["kb_in"] * m * rng.lognormal(-KB_SIGMA ** 2 / 2, KB_SIGMA)))
        fail_wan = int(rng.poisson(BG_FAILED_WAN))                       # 7. scanner noise
        ok = int(rng.poisson(OWNER_LOGIN))                               # 8. owner login

        login_ips = [rand_ip(rng, "203.0.113") for _ in range(fail_wan)]
        usernames = list(rng.choice(USERNAMES, size=fail_wan)) if fail_wan else []
        if ok:
            login_ips.append(f"192.168.1.{rng.integers(2, 60)}")
            usernames.append("admin")

        new_devices = 0                                                   # 9. guest phone
        if self.guest_until < self.minute and rng.random() < GUEST_PROB:
            self.guest_until = self.minute + int(rng.integers(60, 241))
            new_devices = 1

        domains_first = [f"site-{rng.integers(1000, 9999)}.example" for _ in range(min(new_dom, 10))]
        domains_first += [f"trk-{rng.integers(1000, 9999)}.example" for _ in range(min(dns_fail, 10))]
        return {
            "router_id": p.router_id, "ts": ts.strftime(TS_FMT),
            "customer_name": p.customer_name, "account_id": p.account_id, "public_ip": p.public_ip,
            "failed_logins": fail_wan, "failed_logins_wan": fail_wan, "successful_logins": ok,
            "login_sources": 0,
            "outbound_conns": conns, "unique_dest_ips": dests, "new_dest_ips": new_dests,
            "dns_queries": dns, "dns_failures": dns_fail, "new_domains": new_dom,
            "kb_out": max(kb_out, 0), "kb_in": max(kb_in, 0), "devices": 0, "new_devices": new_devices,
            # helper lists, turned into the contract lists by finalize()
            "_login_ips": login_ips, "_usernames": usernames,
            "_dests_first": [rand_ip(rng, "198.19") for _ in range(min(new_dests, 10))],
            "_domains_first": domains_first,
        }

    # --- step 10: fill the lists, enforce the counter rules --------------------------
    def finalize(self, d: dict) -> dict:
        rng, p = self.rng, self.profile
        if "_device_added" in d:
            name = d.pop("_device_added")
            if name not in self.extra_devices:
                self.extra_devices.append(name)
        devs = self.base_devices + self.extra_devices
        if self.guest_until >= self.minute:
            devs = devs + ["Guest-Phone"]
        if len(devs) > MAX_DEVICE_NAMES:  # keep the injection device (last base name) visible
            devs = devs[: MAX_DEVICE_NAMES]
        d["devices"] = len(self.base_devices) + len(self.extra_devices) + (self.guest_until >= self.minute)

        d["unique_dest_ips"] = max(d["unique_dest_ips"], d["new_dest_ips"])
        d["outbound_conns"] = max(d["outbound_conns"], d["unique_dest_ips"])
        d["dns_queries"] = max(d["dns_queries"], d["new_domains"] + d["dns_failures"])
        d["failed_logins"] = max(d["failed_logins"], d["failed_logins_wan"])

        ips = list(dict.fromkeys(d.pop("_login_ips")))
        d["login_sources"] = len(ips)
        d["login_src_ips"] = ips[:MAX_LIST]
        d["usernames_tried"] = [str(u) for u in dict.fromkeys(d.pop("_usernames"))][:MAX_LIST]

        n_dest = min(MAX_LIST, d["unique_dest_ips"])
        first = list(dict.fromkeys(d.pop("_dests_first")))[: min(n_dest, d["new_dest_ips"])]
        fam = _cyclic(p.familiar_dests, int(rng.integers(len(p.familiar_dests))), n_dest - len(first))
        d["dest_ips"] = (first + fam)[:n_dest]

        n_dom = min(MAX_LIST, d["dns_queries"])
        first = list(dict.fromkeys(d.pop("_domains_first")))[:n_dom]
        fam = _cyclic(p.familiar_domains, int(rng.integers(len(p.familiar_domains))), n_dom - len(first))
        d["domains"] = (first + fam)[:n_dom]
        d["device_names"] = devs
        return {k: d[k] for k in RECORD_FIELDS}

    def minute_record(self, ts: datetime, episode: Episode | None = None) -> tuple[dict, dict]:
        """One finished record and its label row, then advance this router's clock."""
        d = self.draft(ts)
        if episode is not None and episode.active(self.minute):
            d, lab = episode.apply(d, self.minute - episode.start)
        else:
            lab = label_row(d)
        rec = self.finalize(d)
        self.minute += 1
        return rec, lab


class Fleet:
    """Live demo fleet (the interface the engine calls)."""

    def __init__(self, n_routers=12, seed=7, start_ts="2026-11-14T18:00:00", id_start=101):
        self.n_routers, self.seed, self.id_start = n_routers, seed, id_start
        self.start = datetime.strptime(start_ts, TS_FMT)
        self.router_ids = [f"R-{id_start + i:03d}" for i in range(n_routers)]
        self.sims = [RouterSim(seed, i, rid) for i, rid in enumerate(self.router_ids)]
        self._by_id = {s.profile.router_id: s for s in self.sims}
        self._trigger_rng = {rid: np.random.default_rng([seed, i, 2]) for i, rid in enumerate(self.router_ids)}
        self.episodes: dict[str, Episode] = {}
        self._truth: list[dict] = []
        self._n_episodes = 0
        self.now = self.start
        self._warmed = False

    # --- the engine interface -------------------------------------------------------
    def warmup(self, hours: int = 24) -> list[dict]:
        """Normal-only history for the `hours` before start_ts, returned at once."""
        out = []
        for s in self.sims:
            s.minute = -hours * 60
        for m in range(hours * 60, 0, -1):
            ts = self.start - timedelta(minutes=m)
            for s in self.sims:
                out.append(s.minute_record(ts)[0])
        self._warmed = True
        return out

    def step(self) -> list[dict]:
        """Advance one simulated minute. One record per router."""
        recs, truth = [], []
        for s in self.sims:
            rid = s.profile.router_id
            ep = self.episodes.get(rid)
            # live botnet: stays quiet until botnet_loud, or 60 minutes pass
            if isinstance(ep, Botnet) and ep.loud_start is None and s.minute - ep.start >= 60:
                ep.go_loud(s.minute - ep.start)
            rec, lab = s.minute_record(self.now, ep)
            recs.append(rec)
            truth.append({k: lab[k] for k in ("router_id", "ts", "label", "scenario", "phase")})
            if ep is not None and s.minute >= ep.start + ep.duration:
                del self.episodes[rid]
        self._truth = truth
        self.now += timedelta(minutes=1)
        return recs

    def trigger(self, router_id: str, scenario: str, intensity: float = 1.0) -> None:
        """Start a scenario on one router from the next step on.

        scenario: botnet, botnet_loud, brute_force_fast, brute_force_slow,
        brute_force, new_device, forgot_password, or reset.
        """
        if scenario == "reset":
            self.reset()
            return
        sim = self._by_id.get(router_id)
        if sim is None:
            raise ValueError(f"unknown router {router_id!r}")
        rng = self._trigger_rng[router_id]
        start = sim.minute
        self._n_episodes += 1
        eid = f"LIVE-{router_id}-E{self._n_episodes}"
        cur = self.episodes.get(router_id)
        if scenario == "botnet_loud":
            if isinstance(cur, Botnet) and cur.active(start):
                cur.go_loud(start - cur.start)
                return
            ep = Botnet(eid, start, rng, intensity=intensity, loud="none", quiet_len=10_000)
            ep.go_loud(0)
        elif scenario == "botnet":
            ep = Botnet(eid, start, rng, intensity=intensity, loud="none", quiet_len=10_000)
        elif scenario in ("brute_force", "brute_force_fast", "brute_force_slow"):
            variant = None if scenario == "brute_force" else scenario.rsplit("_", 1)[1]
            ep = BruteForce(eid, start, rng, intensity=intensity, variant=variant)
        elif scenario == "new_device":
            ep = NewDevice(eid, start, rng)
        elif scenario == "forgot_password":
            ep = ForgotPassword(eid, start, rng)
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        self.episodes[router_id] = ep

    def current_truth(self) -> list[dict]:
        """Labels for the last step. For evaluation and debugging only, never detection."""
        return [dict(t) for t in self._truth]

    def reset(self) -> None:
        """Stop every scenario and remove added devices. The clock keeps running."""
        self.episodes.clear()
        for s in self.sims:
            s.reset_devices()
