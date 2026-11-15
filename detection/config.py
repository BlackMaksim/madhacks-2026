"""Detection settings: feature lists, floors, thresholds and class names.

This is the ONLY place these live (blueprint Section 6E). Change them here and
nowhere else, and announce the change in the team chat.
"""

# --- Record counters (format v1.1, blueprint Section 9) -----------------------

# Per-minute counters that get 10-minute totals. `devices` is a level, not a
# per-minute count, so it is not summed.
COUNTERS_W10 = [
    "failed_logins", "failed_logins_wan", "successful_logins", "login_sources",
    "outbound_conns", "unique_dest_ips", "new_dest_ips",
    "dns_queries", "dns_failures", "new_domains",
    "kb_out", "kb_in", "new_devices",
]

# Slow patterns build up over an hour.
COUNTERS_W60 = [
    "failed_logins_wan", "login_sources", "new_dest_ips",
    "dns_failures", "new_domains", "new_devices",
]

# Compared with the router's own previous 24 hours.
COUNTERS_LR10 = [
    "failed_logins_wan", "login_sources", "outbound_conns", "unique_dest_ips",
    "new_dest_ips", "dns_queries", "dns_failures", "new_domains", "kb_out", "kb_in",
]

# Floors stop near-zero baselines from exploding the log-ratio.
FLOORS = {
    "failed_logins_wan": 1, "login_sources": 1,
    "new_dest_ips": 2, "new_domains": 2, "dns_failures": 2,
    "outbound_conns": 10, "unique_dest_ips": 10, "dns_queries": 10,
    "kb_out": 100, "kb_in": 100,
}

# --- Baseline windows (minutes) ------------------------------------------------

WINDOW_SHORT = 10
WINDOW_LONG = 60
BASELINE_WINDOW = 1440       # previous 24 hours
BASELINE_SHIFT = 60          # shift back so an attack can't raise its own baseline
BASELINE_MIN_PERIODS = 360   # need 6 hours of history before a baseline exists
CHANGE_LAG = 10              # conns_jump / dest_jump compare with 10 minutes earlier

# Rows earlier than this (per router) have no baseline or no jump yet: drop from
# training/eval. 60 shift + 360 minimum history + 10 for the jump features = 430.
MIN_HISTORY_MINUTES = BASELINE_SHIFT + BASELINE_MIN_PERIODS + CHANGE_LAG

# Live buffer size per router (the engine keeps this many minutes). The newest row
# needs 9 (10-min total) + 1440 (baseline) + 60 (shift) + 10 (jump) = 1519 rows; we
# keep 1520 (one spare). A shorter buffer makes live features differ from training.
# The blueprint said 1500; tests/test_features.py::test_batch_equals_live checks this.
LIVE_BUFFER_MINUTES = (WINDOW_SHORT - 1) + BASELINE_WINDOW + BASELINE_SHIFT + CHANGE_LAG + 1

# --- Feature names -------------------------------------------------------------

F_W10 = [f"{c}_w10" for c in COUNTERS_W10]
F_W60 = [f"{c}_w60" for c in COUNTERS_W60]
F_LR10 = [f"{c}_lr10" for c in COUNTERS_LR10]
F_SHAPE = ["kb_per_conn_w10", "dns_fail_ratio_w10", "new_domain_ratio_w10", "wan_fail_share_w10"]
F_FLAGS = ["success_after_fails_w10", "new_device_w60"]
F_CHANGE = ["conns_jump", "dest_jump"]
F_TIME = ["hour_sin", "hour_cos"]
F_LOG = ["log_failed_logins_wan_w60", "log_dns_failures_w60", "log_new_devices_w60", "log_kb_per_conn_w10"]

# Isolation Forest: relative features only, so a busy household isn't
# "unusual" just for being busy. 18 features.
FEATURES_IF = (
    F_LR10
    + ["log_failed_logins_wan_w60", "log_dns_failures_w60", "log_new_devices_w60"]
    + ["log_kb_per_conn_w10", "dns_fail_ratio_w10", "new_domain_ratio_w10"]
    + F_TIME
)

# Random Forest: everything, including raw volumes.
FEATURES_RF = F_W10 + F_W60 + F_LR10 + F_SHAPE + F_FLAGS + F_CHANGE + F_TIME + F_LOG

# Everything build_features() returns (besides router_id and ts).
FEATURES_ALL = list(dict.fromkeys(FEATURES_RF + FEATURES_IF))

# --- Classes and labels ----------------------------------------------------------

CLASSES = ["normal", "benign_unusual", "brute_force", "botnet"]
ATTACK_CLASSES = {"brute_force", "botnet"}

VERDICTS = ["normal", "watch", "unusual_benign", "unknown_anomaly", "known_attack"]
SUSPICIOUS_VERDICTS = {"known_attack", "unusual_benign", "unknown_anomaly"}

INCIDENT_TYPES = ["unusual_benign", "unknown_anomaly", "brute_force", "botnet"]  # low -> high rank
SEVERITIES = ["low", "medium", "high", "critical"]                               # low -> high rank

# --- Thresholds ----------------------------------------------------------------

THRESHOLDS = {
    "anomaly_pct": 0.995,   # Isolation Forest flag; tune on validation routers only
    "class_conf": 0.6,      # classifier confidence needed when flagged
    "watch_conf": 0.8,      # classifier confidence for `watch` when not flagged
    # Not flagged, but the classifier is >= 90% sure it's a harmless look-alike ->
    # `unusual_benign` (low advisory). Added after the blueprint: without it a new
    # smart device often showed nothing. Chosen on validation routers (0.8 also gave
    # advisories for forgotten passwords; 0.9 did not).
    "benign_watch_conf": 0.9,
}

# Severity rules (blueprint Section 6F).
LOUD_LR10 = 2.3              # outbound_conns_lr10 or unique_dest_ips_lr10 >= this -> botnet critical
BRUTE_SUCCESS_MIN_FAILS = 10 # failed_logins_wan_w10 needed with a success -> brute_force high

# Incident manager defaults.
INCIDENT_OPEN_K = 3
INCIDENT_WINDOW = 5
INCIDENT_CLOSE_AFTER = 20
INCIDENT_REOPEN_WITHIN = 30
INCIDENT_MAX_VERSION = 3

# Evidence list for reports.
EVIDENCE_MIN_LR10 = 0.7      # at least ~2x usual
EVIDENCE_TOP_K = 5

# Plain-language meanings for the evidence list (used by P3's payload).
SIGNAL_MEANINGS = {
    "failed_logins_wan": "failed admin logins from outside the home",
    "login_sources": "distinct addresses that tried to log in",
    "outbound_conns": "new outgoing connections",
    "unique_dest_ips": "distinct destinations contacted",
    "new_dest_ips": "destinations this router never contacted before",
    "dns_queries": "domain name lookups",
    "dns_failures": "lookups for domain names that do not exist",
    "new_domains": "domains this router never looked up before",
    "kb_out": "kilobytes sent",
    "kb_in": "kilobytes received",
}

MODEL_VERSION = "stub"
