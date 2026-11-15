"""Attack episodes and harmless look-alikes (blueprint Section 4).

An episode is applied to a "draft" minute: the counters of a normal minute plus a
few helper lists (keys starting with "_") that fleet.finalize() turns into the
contract lists. Each episode has

    apply(record, minute_index) -> (record, label_row)

where minute_index counts minutes since the episode started (0 = first minute).
Labels go into label_row only, never into the record.

Every number is a synthetic demonstration parameter, not a real-world measurement.
"""
from __future__ import annotations

import math

import numpy as np

from simulator.households import USERNAMES

ALNUM = np.array(list("abcdefghijklmnopqrstuvwxyz0123456789"))


# --- small helpers shared with fleet.py -------------------------------------------

def rand_ip(rng: np.random.Generator, prefix: str) -> str:
    """prefix is '198.19', '203.0.113' or '192.168.1'."""
    if prefix.count(".") == 1:
        a, b = rng.integers(0, 256), rng.integers(1, 255)
        return f"{prefix}.{a}.{b}"
    return f"{prefix}.{rng.integers(2, 255)}"


def botnet_domain(rng: np.random.Generator) -> str:
    return "".join(rng.choice(ALNUM, size=12)) + ".example"


def label_row(record: dict, label="normal", scenario="normal", phase="none", episode_id="") -> dict:
    return {"router_id": record["router_id"], "ts": record["ts"], "label": label,
            "scenario": scenario, "phase": phase, "episode_id": episode_id}


def add_dests(rec: dict, n_new: int, ips: list[str]) -> None:
    """n_new new destinations (not in the familiar set), each a new connection."""
    rec["new_dest_ips"] += n_new
    rec["unique_dest_ips"] += n_new
    rec["outbound_conns"] += n_new
    rec["_dests_first"].extend(ips)


# --- base class ------------------------------------------------------------------------

class Episode:
    scenario = "normal"
    label = "normal"

    def __init__(self, episode_id: str, start: int, rng: np.random.Generator, intensity: float = 1.0):
        self.episode_id = episode_id
        self.start = start          # absolute minute index on this router
        self.rng = rng
        self.intensity = float(intensity)
        self.duration = 1
        self.success = None         # brute force only
        self.loud_start = None      # botnet only: offset (minutes) of the loud phase

    def active(self, minute: int) -> bool:
        return self.start <= minute < self.start + self.duration

    def phase(self, t: int) -> str:
        return "none"

    def apply(self, record: dict, minute_index: int):
        raise NotImplementedError

    def row(self, record: dict, t: int) -> dict:
        return label_row(record, self.label, self.scenario, self.phase(t), self.episode_id)


# --- Attack 1: password guessing ----------------------------------------------------------

class BruteForce(Episode):
    label = "brute_force"

    def __init__(self, episode_id, start, rng, intensity=None, variant=None,
                 duration=None, success=None):
        super().__init__(episode_id, start, rng,
                         intensity if intensity is not None else rng.uniform(0.4, 1.6))
        self.variant = variant or str(rng.choice(["fast", "slow"]))
        self.scenario = f"brute_force_{self.variant}"
        self.duration = int(duration if duration is not None else rng.integers(30, 121))
        self.ramp = int(rng.integers(5, 11))
        self.success = bool(success if success is not None else rng.random() < 0.25)
        n_ips = int(rng.integers(1, 4)) if self.variant == "fast" else int(rng.integers(10, 41))
        self.ips = sorted({rand_ip(rng, "203.0.113") for _ in range(n_ips)})
        self.rate = (25.0 if self.variant == "fast" else 3.0) * self.intensity

    def apply(self, record, minute_index):
        t, rng = minute_index, self.rng
        ramp = min(1.0, (t + 1) / self.ramp)
        n = int(rng.poisson(self.rate * ramp))
        if self.variant == "fast":
            srcs = list(rng.choice(self.ips, size=n)) if n else []
        else:  # slow: the IPs take turns, a few per minute
            k = min(len(self.ips), max(1, n))
            turn = [self.ips[(t * 3 + j) % len(self.ips)] for j in range(k)]
            srcs = [turn[j % k] for j in range(n)]
        record["failed_logins_wan"] += n
        record["failed_logins"] += n
        record["_login_ips"].extend(srcs)
        record["_usernames"].extend(rng.choice(USERNAMES, size=min(n, 10)).tolist() if n else [])
        if self.success and t == self.duration - 1:  # the attacker gets in
            record["successful_logins"] += 1
            record["_login_ips"].append(self.ips[0])
            record["_usernames"].append("admin")
        return record, self.row(record, t)


# --- Attack 2: botnet infection -------------------------------------------------------------

class Botnet(Episode):
    label = "botnet"

    def __init__(self, episode_id, start, rng, intensity=None, loud=None,
                 quiet_len=None, loud_len=None, live=False):
        super().__init__(episode_id, start, rng,
                         intensity if intensity is not None else rng.uniform(0.5, 1.5))
        self.live = live  # live demo: loud phase not decided yet, so don't call it quiet_only
        if loud is None:  # 30% stay quiet for the whole episode
            loud = "none" if rng.random() < 0.30 else str(rng.choice(["scan", "ddos"]))
        self.loud = loud
        self.quiet_len = int(quiet_len if quiet_len is not None else rng.integers(20, 61))
        self.loud_len = int(loud_len if loud_len is not None else rng.integers(15, 46))
        self.targets = [rand_ip(rng, "198.19") for _ in range(int(rng.integers(1, 4)))]
        self.c2 = [rand_ip(rng, "198.19") for _ in range(3)]
        self._set_timing()

    @property
    def scenario(self):
        if self.live and self.loud == "none":
            return "botnet"
        return {"none": "botnet_quiet_only", "scan": "botnet_scan", "ddos": "botnet_ddos"}[self.loud]

    def _set_timing(self):
        if self.loud == "none":
            self.loud_start, self.duration = None, self.quiet_len
        else:
            self.loud_start, self.duration = self.quiet_len, self.quiet_len + self.loud_len

    def go_loud(self, t: int, variant: str = "scan", loud_len: int = 15) -> None:
        """Live mode: start the loud phase now (minute offset t)."""
        if self.loud_start is not None and t >= self.loud_start:
            return
        self.loud, self.quiet_len, self.loud_len = variant, t, loud_len
        self._set_timing()

    def phase(self, t):
        return "loud" if self.loud_start is not None and t >= self.loud_start else "quiet"

    def apply(self, record, minute_index):
        t, rng, i = minute_index, self.rng, self.intensity
        # Quiet phase signals continue all episode: random-looking lookups, a few new contacts.
        nd = int(rng.poisson(i * 3))
        nf = int(rng.poisson(i * 4))
        record["new_domains"] += nd
        record["dns_failures"] += nf
        record["dns_queries"] += nd + nf
        record["_domains_first"].extend(botnet_domain(rng) for _ in range(min(nd + nf, 10)))
        nn = int(rng.poisson(i * 1))
        add_dests(record, nn, [self.c2[k % 3] for k in range(min(nn, 10))])
        record["outbound_conns"] += int(rng.poisson(i * 3))
        record["kb_out"] += int(round(i * 20))

        if self.phase(t) == "loud":
            ramp = min(1.0, (t - self.loud_start + 1) / 3.0)
            if self.loud == "scan":  # many tiny probes to new addresses
                n = int(rng.poisson(i * 250 * ramp))
                n_new = int(rng.binomial(n, 0.95))
                add_dests(record, n_new, [rand_ip(rng, "198.19") for _ in range(min(n_new, 10))])
                record["unique_dest_ips"] += n - n_new
                record["outbound_conns"] += n - n_new
                record["kb_out"] += int(round(i * 300 * ramp))
            else:  # ddos: a flood to 1-3 targets
                record["outbound_conns"] += int(rng.poisson(i * 1500 * ramp))
                add_dests(record, len(self.targets), list(self.targets))
                record["kb_out"] += int(round(i * 40000 * ramp))
        return record, self.row(record, t)


# --- Look-alikes (data v2, labeled normal) -------------------------------------------------

class ForgotPassword(Episode):
    scenario = "benign_forgot_password"
    label = "normal"

    def __init__(self, episode_id, start, rng, intensity=1.0):
        super().__init__(episode_id, start, rng, intensity)
        self.fails = int(rng.integers(3, 9))
        self.duration = int(rng.integers(2, 7)) + 1        # fails over 2-6 minutes, then success
        cuts = np.sort(rng.integers(0, self.duration - 1, size=self.fails))
        self.per_minute = np.bincount(cuts, minlength=self.duration - 1)
        self.ip = rand_ip(rng, "192.168.1")

    def apply(self, record, minute_index):
        t = minute_index
        if t < self.duration - 1:
            n = int(self.per_minute[t])
            record["failed_logins"] += n           # LAN only: failed_logins_wan stays 0
            record["_login_ips"].extend([self.ip] * n)
            record["_usernames"].extend(["admin"] * min(n, 10))
        else:
            record["successful_logins"] += 1
            record["_login_ips"].append(self.ip)
            record["_usernames"].append("admin")
        return record, self.row(record, t)


class NewDevice(Episode):
    scenario = "benign_new_device"
    label = "normal"
    NAMES = ["Backyard-Camera", "Smart-Doorbell-2", "Air-Purifier", "Garden-Sensor",
             "Smart-Lock", "Pet-Feeder", "Solar-Inverter", "Kids-Tablet"]

    def __init__(self, episode_id, start, rng, intensity=1.0, name=None):
        super().__init__(episode_id, start, rng, intensity)
        self.duration = 45
        self.name = name or str(rng.choice(self.NAMES))
        self.firmware_kb = int(rng.integers(5000, 30000))
        self.vendor = f"{self.name.lower().split('-')[0]}-vendor.example"

    def apply(self, record, minute_index):
        t, rng = minute_index, self.rng
        fade = math.exp(-t / 15.0)
        if t == 0:
            record["new_devices"] += 1
        record["_device_added"] = self.name   # fleet adds it to the router permanently
        nd = int(rng.poisson(6 * fade))
        record["new_domains"] += nd
        record["dns_queries"] += int(rng.poisson(15 * fade)) + nd
        record["_domains_first"].extend(
            [self.vendor] + [f"{self.name.lower()}-{rng.integers(100, 999)}.example" for _ in range(max(0, min(nd, 9) - 1))]
            if nd else [])
        nn = int(rng.poisson(4 * fade))
        add_dests(record, nn, [rand_ip(rng, "198.19") for _ in range(min(nn, 10))])
        if t < 10:  # firmware download
            record["kb_in"] += self.firmware_kb
        return record, self.row(record, t)


# Live demo names -> episode class. "brute_force" picks a variant at random.
LIVE_SCENARIOS = {"botnet", "botnet_loud", "brute_force", "brute_force_fast", "brute_force_slow",
                  "new_device", "forgot_password", "reset"}
