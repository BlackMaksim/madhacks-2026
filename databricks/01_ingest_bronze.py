# Databricks notebook source
# 01_ingest_bronze (P1.8, blueprint Section 5, Step 3)
#
# Before running: upload the six files made by scripts/prepare_upload.py
# (data/upload/fleetA_records.parquet, fleetA_labels.parquet, fleetA_episodes.csv
# and the same for fleet B) to the raw volume: Catalog > workspace > edgesentinel
# > raw > "Upload to this volume". Use serverless compute; detach when done.
# Data is synthetic. bronze_records holds private fields: only the owner reads it.

from pyspark.sql import functions as F

VOL, CAT = "/Volumes/workspace/edgesentinel/raw", "workspace.edgesentinel"

for fleet in ["A", "B"]:
    rec = spark.read.parquet(f"{VOL}/fleet{fleet}_records.parquet").withColumn("fleet", F.lit(fleet))
    lab = spark.read.parquet(f"{VOL}/fleet{fleet}_labels.parquet").withColumn("fleet", F.lit(fleet))
    epi = spark.read.option("header", True).csv(f"{VOL}/fleet{fleet}_episodes.csv").withColumn("fleet", F.lit(fleet))
    mode = "overwrite" if fleet == "A" else "append"
    rec.write.mode(mode).option("overwriteSchema", "true").saveAsTable(f"{CAT}.bronze_records")
    lab.write.mode(mode).option("overwriteSchema", "true").saveAsTable(f"{CAT}.bronze_labels")
    epi.write.mode(mode).option("overwriteSchema", "true").saveAsTable(f"{CAT}.bronze_episodes")

# COMMAND ----------

# Check: expect A = 172800 and B = 86400
display(spark.sql(f"SELECT fleet, count(*) AS n FROM {CAT}.bronze_records GROUP BY fleet ORDER BY fleet"))
display(spark.sql(f"SELECT fleet, label, count(*) AS n FROM {CAT}.bronze_labels GROUP BY fleet, label ORDER BY fleet, label"))
display(spark.sql(f"SELECT fleet, scenario, count(*) AS n FROM {CAT}.bronze_episodes GROUP BY fleet, scenario ORDER BY fleet, scenario"))
