# Databricks notebook source
# 02_build_silver (E.11, blueprint Section 5, Step 3)
#
# Bronze (raw, private) -> Silver (features, pseudonymized).
# Silver has one row per router-minute with every model feature, but NO customer
# names, account IDs, IP addresses, domains or device names, and the router ID is
# replaced by a one-way token. The models train on Silver, so they never needed
# customer identity.
#
# Before running: upload data/upload/edgesentinel_code.zip (made by
# `python -m databricks.build_code_zip` on a laptop) to the raw volume.
# Use serverless compute; detach when done.

import hashlib
import sys

CODE_ZIP = "/Volumes/workspace/edgesentinel/raw/edgesentinel_code.zip"
CAT = "workspace.edgesentinel"
SALT = "madhacks-2026"   # in a real deployment this would be a secret, not in code

sys.path.insert(0, CODE_ZIP)
import pandas, sklearn
from detection import config as C
from detection.features import build_features

print("pandas", pandas.__version__, "| scikit-learn", sklearn.__version__)
print(len(C.FEATURES_ALL), "features")

# COMMAND ----------

# Read only the columns the features need (no names, IPs or lists leave Bronze).
cols = ["router_id", "ts", "fleet"] + C.COUNTERS_W10
raw = spark.table(f"{CAT}.bronze_records").select(*cols).toPandas()
print(f"{len(raw):,} Bronze rows")

feats = build_features(raw)                      # the same function the live laptop uses
feats = feats.merge(raw[["router_id", "fleet"]].drop_duplicates(), on="router_id", how="left")
feats["router_token"] = feats["router_id"].map(
    lambda r: hashlib.sha256((SALT + r).encode()).hexdigest()[:10])

silver = feats[["router_token", "ts", "fleet"] + C.FEATURES_ALL]   # router_id dropped here
spark.createDataFrame(silver).write.mode("overwrite").option("overwriteSchema", "true") \
     .saveAsTable(f"{CAT}.silver_features")
print(f"wrote {CAT}.silver_features: {len(silver):,} rows x {silver.shape[1]} columns")

# COMMAND ----------

# Check 1: row counts per fleet (expect A = 172800, B = 86400) and 60 + 30 tokens.
display(spark.sql(f"""
    SELECT fleet, count(*) AS rows, count(DISTINCT router_token) AS routers
    FROM {CAT}.silver_features GROUP BY fleet ORDER BY fleet"""))

# COMMAND ----------

# Check 2: no private column made it into Silver.
private = {"router_id", "customer_name", "account_id", "public_ip", "login_src_ips",
           "usernames_tried", "dest_ips", "domains", "device_names"}
leaked = private & set(spark.table(f"{CAT}.silver_features").columns)
assert not leaked, f"private columns in Silver: {leaked}"
print("Silver contains no private columns:", sorted(private))
