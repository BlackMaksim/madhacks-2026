# Databricks notebook source
# 03_train_evaluate (E.11, blueprint Section 5, Step 3)
#
# Train both models on SILVER (pseudonymized features: router tokens, no customer
# identity), evaluate them against the rules baseline, and record everything in
# MLflow: parameters, headline metrics, the full evaluation report, and the model file.
#
# The same training code builds the laptop's live model (Plan B). This run is the
# tracked, governed version of it.
# Needs: bronze_* and silver_features tables, and edgesentinel_code.zip in the raw volume.

import hashlib
import json
import sys

CODE_ZIP = "/Volumes/workspace/edgesentinel/raw/edgesentinel_code.zip"
CAT = "workspace.edgesentinel"
SALT = "madhacks-2026"           # must match 02_build_silver
MODEL_PATH = "/Volumes/workspace/edgesentinel/models/edgesentinel_v2_dbx.joblib"

sys.path.insert(0, CODE_ZIP)
import mlflow
import sklearn
from detection import config as C
from detection.evaluate import _json_default, evaluate_all
from detection.train import save_bundle, split_routers, train_models


def token(r: str) -> str:
    return hashlib.sha256((SALT + r).encode()).hexdigest()[:10]


print("scikit-learn", sklearn.__version__, "| mlflow", mlflow.__version__)

# COMMAND ----------

# Training data: fleet A from Silver. Labels come from Bronze and are joined by token,
# so the models only ever see pseudonymized rows.
feats_a = (spark.table(f"{CAT}.silver_features").where("fleet = 'A'").toPandas()
           .rename(columns={"router_token": "router_id"}))          # train on tokens
labels_a = spark.table(f"{CAT}.bronze_labels").where("fleet = 'A'").toPandas()
real_ids = sorted(labels_a["router_id"].unique())
labels_a["router_id"] = labels_a["router_id"].map(token)

# The same router split as the laptop model: split the real IDs, then switch to tokens.
train_ids, val_ids, test_ids = split_routers(real_ids, seed=42)
train_tok, val_tok = [token(r) for r in train_ids], [token(r) for r in val_ids]
print(f"fleet A: {len(feats_a):,} feature rows | train {len(train_ids)} / val {len(val_ids)} / test {len(test_ids)} routers")

bundle = train_models(feats_a, labels_a, train_tok, val_tok, version="v2-dbx", seed=42)
bundle["split"]["test"] = [token(r) for r in test_ids]
print("trained; classes:", bundle["classes"], "| RF rows per class:", bundle["rf_class_counts"])

# COMMAND ----------

# Evaluation (internal, so it may read Bronze): fleet A test routers and all of fleet B,
# our models vs Person 1's rules baseline, through the same incident logic.
def load(fleet, keep=None):
    cols = ["router_id", "ts"] + C.COUNTERS_W10
    r = spark.table(f"{CAT}.bronze_records").where(f"fleet = '{fleet}'").select(*cols).toPandas()
    l = spark.table(f"{CAT}.bronze_labels").where(f"fleet = '{fleet}'").toPandas()
    e = spark.table(f"{CAT}.bronze_episodes").where(f"fleet = '{fleet}'").toPandas()
    if keep is not None:
        r, l, e = r[r.router_id.isin(keep)], l[l.router_id.isin(keep)], e[e.router_id.isin(keep)]
    return r, l, e

report = evaluate_all(bundle, {"fleetA_test": load("A", set(test_ids)), "fleetB": load("B")})
for k, v in report["headline"].items():
    if k.startswith("fleetB"):
        print(f"{k:45s} {v}")

# COMMAND ----------

# Record the run in MLflow and save the model file to the models volume.
user = spark.sql("SELECT current_user()").first()[0]
# Inside the edgesentinel notebook folder; the folder itself can't also be an experiment.
mlflow.set_experiment(f"/Users/{user}/edgesentinel/edgesentinel_runs")
with mlflow.start_run(run_name="v2_if_rf") as run:
    mlflow.log_params(bundle["params"])
    mlflow.log_param("trained_on", "silver_features (pseudonymized), fleet A")
    mlflow.log_metrics(report["headline"])
    mlflow.log_dict(json.loads(json.dumps(report, default=_json_default)), "eval_report.json")
    save_bundle(bundle, MODEL_PATH)
    mlflow.log_artifact(MODEL_PATH)
print("MLflow run:", run.info.run_id, "| model saved to", MODEL_PATH)
