# Databricks notebook source
# 04_gold_history (E.11, blueprint Section 5, Steps 2-3)
#
# Gold = results and history, with no private data (routers appear as tokens):
#   gold_minute_scores    every test-set minute: anomaly percentile, class confidences, verdict
#   gold_episode_results  one row per attack or look-alike episode, for our models AND the
#                         rules baseline: caught or not, delay, what it was called
#   gold_fleet_daily      per router per day: minutes flagged, suspicious minutes, incidents
#
# Uses the model file notebook 03 saved to the models volume (no retraining).
# Needs: bronze_* tables, edgesentinel_code.zip in the raw volume, 03 run once.

import hashlib
import sys

CODE_ZIP = "/Volumes/workspace/edgesentinel/raw/edgesentinel_code.zip"
CAT = "workspace.edgesentinel"
SALT = "madhacks-2026"           # must match 02_build_silver
MODEL_PATH = "/Volumes/workspace/edgesentinel/models/edgesentinel_v2_dbx.joblib"

sys.path.insert(0, CODE_ZIP)
import pandas as pd
from detection import config as C
from detection.detector import load_bundle, score_rows
from detection.evaluate import replay_incidents, score_episodes
from detection.features import build_features
from detection.rules_baseline import score_rows as rules_score_rows
from detection.train import split_routers


def token(r: str) -> str:
    return hashlib.sha256((SALT + r).encode()).hexdigest()[:10]


bundle = load_bundle(MODEL_PATH)
print("model", bundle["version"], "trained", bundle["trained_at"])

# COMMAND ----------

# Score fleet A's test routers and all of fleet B, then replay incidents.
def load(fleet, keep=None):
    cols = ["router_id", "ts"] + C.COUNTERS_W10
    r = spark.table(f"{CAT}.bronze_records").where(f"fleet = '{fleet}'").select(*cols).toPandas()
    l = spark.table(f"{CAT}.bronze_labels").where(f"fleet = '{fleet}'").select("router_id", "ts", "label", "scenario").toPandas()
    e = spark.table(f"{CAT}.bronze_episodes").where(f"fleet = '{fleet}'").toPandas()
    if keep is not None:
        r, l, e = r[r.router_id.isin(keep)], l[l.router_id.isin(keep)], e[e.router_id.isin(keep)]
    return r, l, e

real_a = sorted(spark.table(f"{CAT}.bronze_labels").where("fleet = 'A'").select("router_id").distinct().toPandas()["router_id"])
_, _, test_a = split_routers(real_a, seed=42)          # the same test routers as training used

minutes, episodes, daily = [], [], []
for fleet, keep in (("A", set(test_a)), ("B", None)):
    records, labels, eps = load(fleet, keep)
    feats = build_features(records)
    scores = score_rows(bundle, feats)
    events = replay_incidents(scores, feats)

    m = scores.merge(labels, on=["router_id", "ts"], how="left").assign(fleet=fleet)
    minutes.append(m)

    for detector, scorer in (("models", None), ("rules", rules_score_rows)):
        ev = events if scorer is None else replay_incidents(scorer(bundle, feats), feats)
        episodes.append(score_episodes(ev, eps).assign(detector=detector, fleet=fleet))

    m["day"] = m["ts"].str[:10]
    opened = events[events["event"] == "opened"].assign(day=lambda d: d["ts"].str[:10])
    d = m.groupby(["router_id", "day"]).agg(
        minutes=("ts", "size"), minutes_flagged=("flagged", "sum"),
        minutes_suspicious=("verdict", lambda v: int(v.isin(C.SUSPICIOUS_VERDICTS).sum())))
    d["incidents_opened"] = opened.groupby(["router_id", "day"]).size()
    daily.append(d.fillna({"incidents_opened": 0}).reset_index().assign(fleet=fleet))
    print(f"fleet {fleet}: {len(m):,} minutes, {opened.shape[0]} incidents, {len(eps)} episodes")

# COMMAND ----------

# Tokens instead of router IDs, simple column types, then save the three Gold tables.
def to_gold(df):
    df = df.copy()
    df.insert(0, "router_token", df.pop("router_id").map(token))
    return df

gold_minutes = to_gold(pd.concat(minutes, ignore_index=True).drop(columns=["day"]))
gold_minutes["flagged"] = gold_minutes["flagged"].astype(bool)

gold_episodes = to_gold(pd.concat(episodes, ignore_index=True))
gold_episodes["intensity"] = pd.to_numeric(gold_episodes["intensity"], errors="coerce")
gold_episodes["caught"] = gold_episodes["caught"].astype(bool)
gold_episodes["early"] = gold_episodes["early"].astype("boolean")       # True / False / empty
for c in ("loud_start_ts", "success", "called", "max_sev", "episode_id"):
    gold_episodes[c] = gold_episodes[c].astype("string")
gold_episodes = gold_episodes.drop(columns=[c for c in ("_rescued_data",) if c in gold_episodes])

gold_daily = to_gold(pd.concat(daily, ignore_index=True))
gold_daily = gold_daily.astype({"minutes": int, "minutes_flagged": int, "minutes_suspicious": int, "incidents_opened": int})

for name, df in (("gold_minute_scores", gold_minutes), ("gold_episode_results", gold_episodes),
                 ("gold_fleet_daily", gold_daily)):
    spark.createDataFrame(df).write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(f"{CAT}.{name}")
    print(f"wrote {CAT}.{name}: {len(df):,} rows")

# COMMAND ----------

# Check: models vs rules, straight from Gold.
display(spark.sql(f"""
    SELECT fleet, detector,
           count(*) FILTER (WHERE label != 'normal')                        AS attacks,
           round(avg(CASE WHEN caught THEN 1 ELSE 0 END) FILTER (WHERE label != 'normal'), 3) AS attack_recall,
           percentile(delay_min, 0.5) FILTER (WHERE label != 'normal')       AS median_delay_min,
           count(*) FILTER (WHERE label = 'normal' AND called IN ('botnet', 'brute_force')) AS lookalikes_called_attack
    FROM {CAT}.gold_episode_results GROUP BY fleet, detector ORDER BY fleet, detector"""))

# COMMAND ----------

# Fleet history: the routers with the most incidents.
display(spark.sql(f"""
    SELECT router_token, fleet, sum(incidents_opened) AS incidents, sum(minutes_flagged) AS minutes_flagged
    FROM {CAT}.gold_fleet_daily GROUP BY router_token, fleet ORDER BY incidents DESC LIMIT 10"""))
