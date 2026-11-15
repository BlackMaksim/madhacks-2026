"""Exercise the actual chart renderers without starting the dashboard or live DB."""

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from app import db
from detection import config


def test_live_renderers_follow_newest_persisted_tick(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "charts.db")
    db.init_db()
    path = Path(__file__).resolve().parents[1] / "app/dashboard.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in {
            "_render_router_chart", "_render_classifier"
        }:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in {
                "CHART_SIGNALS", "CLASS_PROBABILITIES"
            } for target in node.targets
        ):
            nodes.append(node)
    st = MagicMock()
    namespace = dict(st=st, db=db, pd=pd, px=px, go=go,
                     make_subplots=make_subplots, detection_config=config)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    for ts, failures, probability in [
        ("2026-11-21T19:02:00", 2, 0.1),
        ("2026-11-21T19:03:00", 40, 0.9),
    ]:
        db.insert_records([dict(router_id="R-107", ts=ts, dns_failures=failures)])
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO scores (router_id,ts,p_botnet,anomaly_pct,verdict) "
                "VALUES (?,?,?,?,?)", ("R-107", ts, probability, probability, "watch")
            )
        namespace["_render_router_chart"]("R-107")
        chart = st.plotly_chart.call_args.args[0]
        assert chart.data[0].x[-1] == ts
        assert chart.data[0].y[-1] == failures
        namespace["_render_classifier"]("R-107")
        classifier = st.plotly_chart.call_args.args[0]
        bars = dict(zip(classifier.data[0].y, classifier.data[0].x))
        assert bars["Botnet"] == probability
