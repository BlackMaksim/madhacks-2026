"""Live simulator, detection, incident, and SQLite coordination loop."""

from __future__ import annotations

import argparse
import logging
import os
import time
from datetime import datetime, timedelta

import pandas as pd

from app import db
from contracts.models import Incident, ScoreRow
from detection import config
from detection.detector import load_bundle, score_rows
from detection.features import build_features
from detection.incidents import IncidentManager
from simulator.fleet import Fleet


LOGGER = logging.getLogger("edgesentinel.engine")
DEFAULT_MODEL_PATH = "models/edgesentinel_v2.joblib"
DEFAULT_WARMUP_HOURS = 24
CHART_HISTORY_MINUTES = 180


def new_incident_manager() -> IncidentManager:
    """Keep new incident IDs distinct from persisted pre-restart history."""
    return IncidentManager(next_id=db.next_incident_number())


def initialize_fleet() -> tuple[Fleet, pd.DataFrame]:
    """Start a new simulator session after retained history, without overwriting it.

    This preserves clock ordering; it does not restore prior attack episodes or
    the previous simulator's random state.
    """
    latest_ts = db.latest_simulation_timestamp()
    if latest_ts is None:
        fleet = Fleet(n_routers=12, seed=7)
    else:
        start = datetime.fromisoformat(latest_ts) + timedelta(minutes=1)
        fleet = Fleet(n_routers=12, seed=7, start_ts=start.isoformat(timespec="seconds"))
        LOGGER.info("Starting a new simulator session after retained timestamp %s", latest_ts)
    buffer = warmup_buffer(fleet)
    # Warmup is synthetic inference context. On restart it must not replace
    # actual persisted telemetry from the previous session.
    if latest_ts is None:
        db.insert_records(chart_seed_records(buffer))
    return fleet, buffer


def warmup_buffer(fleet: Fleet, hours: int = DEFAULT_WARMUP_HOURS) -> pd.DataFrame:
    """Build the initial feature history supplied by the simulator."""
    records = fleet.warmup(hours=hours)
    if not records:
        raise RuntimeError("The simulator returned no warmup records.")
    return pd.DataFrame(records)


def chart_seed_records(buffer: pd.DataFrame) -> list[dict]:
    """Keep a small warmup slice for the dashboard's first chart view."""
    return (
        buffer.sort_values("ts")
        .groupby("router_id", sort=False)
        .tail(CHART_HISTORY_MINUTES)
        .to_dict("records")
    )


def status_rows(scores: list[dict], incidents: IncidentManager) -> list[dict]:
    """Translate detector and incident state into dashboard status colors."""
    rows = []
    for score in scores:
        router_id = score["router_id"]
        incident = incidents.open_incident_for(router_id)

        if incident is not None:
            severity = incident["severity"]
            status = {
                "low": "watch",
                "medium": "warning",
                "high": "critical",
                "critical": "critical",
            }[severity]
            open_incident_id = incident["incident_id"]
        else:
            open_incident_id = None
            verdict = score["verdict"]
            if verdict == "normal":
                status = "healthy"
            elif verdict in {"watch", "unusual_benign"}:
                status = "watch"
            else:
                status = "warning"

        rows.append(
            {
                "router_id": router_id,
                "ts": score["ts"],
                "status": status,
                "verdict": score["verdict"],
                "anomaly_pct": score["anomaly_pct"],
                "open_incident_id": open_incident_id,
            }
        )
    return rows


def _reset_live_state(
    fleet: Fleet,
    buffer: pd.DataFrame,
) -> tuple[pd.DataFrame, IncidentManager]:
    """Clear demo state without rewinding the simulator's clock or history."""
    fleet.reset()
    db.reset_db()
    db.insert_records(chart_seed_records(buffer))
    return buffer, IncidentManager()


def process_tick(
    fleet: Fleet,
    buffer: pd.DataFrame,
    bundle: dict,
    incidents: IncidentManager,
) -> tuple[pd.DataFrame, IncidentManager]:
    """Process one simulated minute and persist its outputs."""
    for command in db.pending_commands():
        if command["command"] == "reset":
            # reset_db clears the command row as part of clearing the live demo.
            buffer, incidents = _reset_live_state(fleet, buffer)
            break

        fleet.trigger(command["router_id"], command["command"])
        db.mark_command_done(command["id"])

    new_records = fleet.step()
    if not new_records:
        raise RuntimeError("The simulator returned no records for this tick.")

    new_frame = pd.DataFrame(new_records)
    buffer = (
        pd.concat([buffer, new_frame], ignore_index=True)
        .sort_values(["router_id", "ts"], kind="stable")
        .groupby("router_id", sort=False)
        .tail(config.LIVE_BUFFER_MINUTES)
        .reset_index(drop=True)
    )

    feature_frame = build_features(buffer)
    latest_features = (
        feature_frame.sort_values("ts", kind="stable")
        .groupby("router_id", sort=False)
        .tail(1)
        .reset_index(drop=True)
    )

    scored_frame = score_rows(bundle, latest_features)
    score_dicts = [
        ScoreRow.model_validate(row).model_dump()
        for row in scored_frame.to_dict("records")
    ]
    feature_dicts = latest_features.to_dict("records")

    db.insert_records(new_records)
    db.insert_scores(score_dicts)

    for score, feature in zip(score_dicts, feature_dicts, strict=True):
        event = incidents.update(score, feature)
        if event is None:
            continue

        incident = Incident.model_validate(event["incident"]).model_dump()
        db.upsert_incident(incident)
        if event["event"] in {"opened", "escalated"}:
            db.request_report(incident["incident_id"], incident["version"])

    db.upsert_status(status_rows(score_dicts, incidents))
    db.insert_truth(fleet.current_truth())
    return buffer, incidents


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the EdgeSentinel live engine")
    parser.add_argument(
        "--once",
        action="store_true",
        help="process one simulated minute, then exit",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    db.init_db()
    bundle_path = os.getenv("MODEL_PATH", DEFAULT_MODEL_PATH)
    bundle = load_bundle(bundle_path)
    fleet, buffer = initialize_fleet()
    incidents = new_incident_manager()

    tick_seconds = max(0.0, float(os.getenv("TICK_SECONDS", "1")))
    LOGGER.info(
        "Engine started with %d routers, %d warmup minutes per router, and model %s",
        buffer["router_id"].nunique(),
        config.LIVE_BUFFER_MINUTES,
        bundle.get("version", "unknown"),
    )

    try:
        while True:
            started = time.perf_counter()
            buffer, incidents = process_tick(fleet, buffer, bundle, incidents)
            if args.once:
                return
            time.sleep(max(0.0, tick_seconds - (time.perf_counter() - started)))
    except KeyboardInterrupt:
        LOGGER.info("Engine stopped by user.")


if __name__ == "__main__":
    main()
