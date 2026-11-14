"""SQLite storage shared by the EdgeSentinel programs."""

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# You can set EDGESENTINEL_DB to use a different database location.
# If it is not set, live.db is created in the project folder.
DB_PATH = Path(os.getenv("EDGESENTINEL_DB", "live.db"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_records (
    router_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (router_id, ts)
);

CREATE TABLE IF NOT EXISTS scores (
    router_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    anomaly_score REAL,
    anomaly_pct REAL,
    flagged INTEGER,
    p_normal REAL,
    p_benign_unusual REAL,
    p_brute_force REAL,
    p_botnet REAL,
    predicted_class TEXT,
    class_conf REAL,
    verdict TEXT,
    PRIMARY KEY (router_id, ts)
);

CREATE TABLE IF NOT EXISTS router_status (
    router_id TEXT PRIMARY KEY,
    ts TEXT,
    status TEXT,
    verdict TEXT,
    anomaly_pct REAL,
    open_incident_id TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    router_id TEXT,
    status TEXT,
    opened_ts TEXT,
    last_ts TEXT,
    closed_ts TEXT,
    version INTEGER,
    incident_type TEXT,
    severity TEXT,
    incident_json TEXT
);

CREATE TABLE IF NOT EXISTS report_queue (
    incident_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at TEXT,
    PRIMARY KEY (incident_id, version)
);

CREATE TABLE IF NOT EXISTS reports (
    incident_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    source TEXT,
    model TEXT,
    created_at TEXT,
    latency_ms INTEGER,
    error TEXT,
    report_json TEXT,
    PRIMARY KEY (incident_id, version)
);

CREATE TABLE IF NOT EXISTS privacy_audit (
    incident_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT,
    raw_snapshot TEXT,
    sent_payload TEXT,
    transformations TEXT,
    token_map TEXT,
    leak_check TEXT,
    bytes_raw INTEGER,
    bytes_sent INTEGER,
    PRIMARY KEY (incident_id, version)
);

CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT,
    command TEXT NOT NULL,
    router_id TEXT,
    done INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS truth (
    router_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    label TEXT,
    scenario TEXT,
    phase TEXT,
    PRIMARY KEY (router_id, ts)
);

CREATE INDEX IF NOT EXISTS idx_raw_records_router_ts
    ON raw_records (router_id, ts);

CREATE INDEX IF NOT EXISTS idx_scores_router_ts
    ON scores (router_id, ts);

CREATE INDEX IF NOT EXISTS idx_incidents_router_status
    ON incidents (router_id, status);

CREATE INDEX IF NOT EXISTS idx_commands_done_id
    ON commands (done, id);
"""


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back on context exit, then release the database file."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect() -> sqlite3.Connection:
    """Open the shared database and enable SQLite's concurrent-read mode."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH, timeout=10, factory=ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db() -> None:
    """Create the tables and indexes if they do not already exist."""
    with connect() as connection:
        connection.executescript(SCHEMA)

def insert_records(records: list[dict]) -> None:
    """Save router records as JSON, one row per router per simulated minute."""
    if not records:
        return

    rows = [
        (
            record["router_id"],
            record["ts"],
            json.dumps(record, ensure_ascii=False),
        )
        for record in records
    ]

    with connect() as connection:
        connection.executemany(
            """
            INSERT OR REPLACE INTO raw_records (router_id, ts, record_json)
            VALUES (?, ?, ?)
            """,
            rows,
        )


def insert_scores(rows: list[dict]) -> None:
    """Save one model score per router per simulated minute."""
    if not rows:
        return

    columns = (
        "router_id",
        "ts",
        "anomaly_score",
        "anomaly_pct",
        "flagged",
        "p_normal",
        "p_benign_unusual",
        "p_brute_force",
        "p_botnet",
        "predicted_class",
        "class_conf",
        "verdict",
    )

    values = []
    for row in rows:
        values.append(
            tuple(
                int(row[column]) if column == "flagged" else row.get(column)
                for column in columns
            )
        )

    placeholders = ", ".join("?" for _ in columns)
    column_names = ", ".join(columns)

    with connect() as connection:
        connection.executemany(
            f"""
            INSERT OR REPLACE INTO scores ({column_names})
            VALUES ({placeholders})
            """,
            values,
        )


def upsert_status(rows: list[dict]) -> None:
    """Save each router's latest status, updating its row if it already exists."""
    if not rows:
        return

    values = [
        (
            row["router_id"],
            row.get("ts"),
            row.get("status"),
            row.get("verdict"),
            row.get("anomaly_pct"),
            row.get("open_incident_id"),
        )
        for row in rows
    ]

    with connect() as connection:
        connection.executemany(
            """
            INSERT INTO router_status (
                router_id, ts, status, verdict, anomaly_pct, open_incident_id
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(router_id) DO UPDATE SET
                ts = excluded.ts,
                status = excluded.status,
                verdict = excluded.verdict,
                anomaly_pct = excluded.anomaly_pct,
                open_incident_id = excluded.open_incident_id
            """,
            values,
        )


def upsert_incident(incident: dict) -> None:
    """Save the incident fields and the complete incident as JSON."""
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, router_id, status, opened_ts, last_ts, closed_ts,
                version, incident_type, severity, incident_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                router_id = excluded.router_id,
                status = excluded.status,
                opened_ts = excluded.opened_ts,
                last_ts = excluded.last_ts,
                closed_ts = excluded.closed_ts,
                version = excluded.version,
                incident_type = excluded.incident_type,
                severity = excluded.severity,
                incident_json = excluded.incident_json
            """,
            (
                incident["incident_id"],
                incident.get("router_id"),
                incident.get("status"),
                incident.get("opened_ts"),
                incident.get("last_ts"),
                incident.get("closed_ts"),
                incident.get("version"),
                incident.get("incident_type"),
                incident.get("severity"),
                json.dumps(incident, ensure_ascii=False),
            ),
        )

def insert_command(command: str, router_id: str | None) -> None:
    """Add a dashboard request for the engine to handle."""
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO commands (created_at, command, router_id)
            VALUES (?, ?, ?)
            """,
            (created_at, command, router_id),
        )


def pending_commands() -> list[dict]:
    """Return dashboard commands the engine has not handled yet."""
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, command, router_id, done
            FROM commands
            WHERE done = 0
            ORDER BY id
            """
        ).fetchall()

    return [dict(row) for row in rows]


def mark_command_done(command_id: int) -> None:
    """Mark a command as handled so the engine will not repeat it."""
    with connect() as connection:
        connection.execute(
            "UPDATE commands SET done = 1 WHERE id = ?",
            (command_id,),
        )


def router_ids() -> list[str]:
    """Return router IDs currently known to the database."""
    with connect() as connection:
        rows = connection.execute(
            "SELECT router_id FROM router_status ORDER BY router_id"
        ).fetchall()

    return [row["router_id"] for row in rows]


def fleet_summary() -> dict:
    """Return the headline counts shown at the top of the dashboard."""
    with connect() as connection:
        router_count = connection.execute(
            "SELECT COUNT(*) FROM router_status"
        ).fetchone()[0]

        open_incidents = connection.execute(
            "SELECT incident_id, severity FROM incidents WHERE status = 'open'"
        ).fetchall()

        report_counts = connection.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM reports
            GROUP BY source
            """
        ).fetchall()

    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    highest_severity = max(
        (row["severity"] for row in open_incidents),
        key=lambda severity: severity_order.get(severity, 0),
        default=None,
    )

    reports_by_source = {
        row["source"]: row["count"]
        for row in report_counts
        if row["source"] is not None
    }

    return {
        "routers_monitored": router_count,
        "open_incidents": len(open_incidents),
        "highest_open_severity": highest_severity,
        "ai_reports": reports_by_source.get("openai", 0),
        "template_reports": reports_by_source.get("fallback", 0),
    }


def latest_status() -> list[dict]:
    """Return the current status row for each router."""
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT router_id, ts, status, verdict, anomaly_pct, open_incident_id
            FROM router_status
            ORDER BY router_id
            """
        ).fetchall()

    return [dict(row) for row in rows]


def recent_records(router_id: str, minutes: int) -> list[dict]:
    """Return recent router records in oldest-to-newest order."""
    limit = max(0, int(minutes))

    with connect() as connection:
        rows = connection.execute(
            """
            SELECT record_json
            FROM raw_records
            WHERE router_id = ?
            ORDER BY ts DESC
            LIMIT ?
            """,
            (router_id, limit),
        ).fetchall()

    # The database query reads newest first to apply LIMIT.
    # Reverse the result so charts receive oldest first.
    return [json.loads(row["record_json"]) for row in reversed(rows)]


def recent_scores(router_id: str, minutes: int) -> list[dict]:
    """Return recent model scores in oldest-to-newest order."""
    limit = max(0, int(minutes))

    with connect() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM scores
            WHERE router_id = ?
            ORDER BY ts DESC
            LIMIT ?
            """,
            (router_id, limit),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def latest_score(router_id: str) -> dict | None:
    """Return the newest score for one router, or None if it has no scores."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM scores
            WHERE router_id = ?
            ORDER BY ts DESC
            LIMIT 1
            """,
            (router_id,),
        ).fetchone()

    return dict(row) if row is not None else None


def open_or_latest_incident(router_id: str) -> dict | None:
    """Return the router's newest open incident, or newest incident if none are open."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT incident_json
            FROM incidents
            WHERE router_id = ?
            ORDER BY
                CASE WHEN status = 'open' THEN 0 ELSE 1 END,
                opened_ts DESC
            LIMIT 1
            """,
            (router_id,),
        ).fetchone()

    return json.loads(row["incident_json"]) if row is not None else None


def latest_report(incident_id: str) -> dict | None:
    """Return the newest saved report for an incident."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT incident_id, version, source, model, created_at,
                   latency_ms, error, report_json
            FROM reports
            WHERE incident_id = ?
            ORDER BY version DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["report"] = json.loads(result.pop("report_json"))
    return result


def latest_audit(incident_id: str) -> dict | None:
    """Return the newest privacy audit for an incident."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT incident_id, version, created_at, raw_snapshot, sent_payload,
                   transformations, token_map, leak_check, bytes_raw, bytes_sent
            FROM privacy_audit
            WHERE incident_id = ?
            ORDER BY version DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)

    # These columns contain JSON text, so turn them back into Python values.
    for column in (
        "raw_snapshot",
        "sent_payload",
        "transformations",
        "token_map",
        "leak_check",
    ):
        if result[column] is not None:
            result[column] = json.loads(result[column])

    return result

def insert_truth(rows: list[dict]) -> None:
    """Save simulator ground-truth labels for later evaluation."""
    if not rows:
        return

    values = [
        (
            row["router_id"],
            row["ts"],
            row.get("label"),
            row.get("scenario"),
            row.get("phase"),
        )
        for row in rows
    ]

    with connect() as connection:
        connection.executemany(
            """
            INSERT OR REPLACE INTO truth (
                router_id, ts, label, scenario, phase
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            values,
        )


def request_report(incident_id: str, version: int) -> None:
    """Queue a report request, without adding the same request twice."""
    requested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connect() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO report_queue (
                incident_id, version, status, requested_at
            )
            VALUES (?, ?, 'pending', ?)
            """,
            (incident_id, version, requested_at),
        )


def claim_report_request() -> dict | None:
    """Claim the oldest pending report request for the reporter to handle."""
    with connect() as connection:
        # Lock the database for this short transaction so two reporter
        # processes cannot claim the same request at the same time.
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT incident_id, version
            FROM report_queue
            WHERE status = 'pending'
            ORDER BY requested_at, incident_id, version
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            return None

        connection.execute(
            """
            UPDATE report_queue
            SET status = 'in_progress'
            WHERE incident_id = ? AND version = ? AND status = 'pending'
            """,
            (row["incident_id"], row["version"]),
        )

        return {
            "incident_id": row["incident_id"],
            "version": row["version"],
        }


def get_incident(incident_id: str) -> dict:
    """Return the full incident object, or raise an error if it is missing."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT incident_json
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

    if row is None:
        raise KeyError(f"Incident not found: {incident_id}")

    return json.loads(row["incident_json"])


def save_report(
    incident_id: str,
    version: int,
    source: str,
    model: str | None,
    latency_ms: int,
    error: str | None,
    report: dict,
) -> None:
    """Save an AI-generated or fallback report."""
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connect() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO reports (
                incident_id, version, source, model, created_at,
                latency_ms, error, report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                version,
                source,
                model,
                created_at,
                latency_ms,
                error,
                json.dumps(report, ensure_ascii=False),
            ),
        )


def save_audit(audit: dict) -> None:
    """Save the privacy audit, including the exact payload and leak-check result."""
    json_columns = (
        "raw_snapshot",
        "sent_payload",
        "transformations",
        "token_map",
        "leak_check",
    )

    def encode_json(value):
        if value is None:
            return None
        return json.dumps(value, ensure_ascii=False)

    with connect() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO privacy_audit (
                incident_id, version, created_at, raw_snapshot, sent_payload,
                transformations, token_map, leak_check, bytes_raw, bytes_sent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit["incident_id"],
                audit["version"],
                audit.get("created_at"),
                *(
                    encode_json(audit.get(column))
                    for column in json_columns
                ),
                audit.get("bytes_raw"),
                audit.get("bytes_sent"),
            ),
        )


def finish_report_request(
    incident_id: str,
    version: int,
    status: str,
) -> None:
    """Mark a claimed report request as done or failed."""
    if status not in {"done", "failed"}:
        raise ValueError("Report request status must be 'done' or 'failed'.")

    with connect() as connection:
        connection.execute(
            """
            UPDATE report_queue
            SET status = ?
            WHERE incident_id = ? AND version = ?
            """,
            (status, incident_id, version),
        )


def reset_db() -> None:
    """Delete saved demo data while keeping the database tables."""
    tables = (
        "raw_records",
        "scores",
        "router_status",
        "incidents",
        "report_queue",
        "reports",
        "privacy_audit",
        "commands",
        "truth",
    )

    with connect() as connection:
        for table in tables:
            connection.execute(f"DELETE FROM {table}")

def selftest() -> None:
    """Exercise every database table using a temporary database file."""
    global DB_PATH

    expected = (
        "raw_records",
        "scores",
        "router_status",
        "incidents",
        "report_queue",
        "reports",
        "privacy_audit",
        "commands",
        "truth",
    )
    original_path = DB_PATH

    with tempfile.TemporaryDirectory(prefix="edgesentinel-db-selftest-") as folder:
        DB_PATH = Path(folder) / "selftest.db"
        try:
            init_db()
            ts = "2026-11-14T19:47:00"
            router_id = "R-SELFTEST"
            incident_id = "INC-SELFTEST"

            record = {"router_id": router_id, "ts": ts, "dns_failures": 2}
            insert_records([record])

            score = {
                "router_id": router_id,
                "ts": ts,
                "anomaly_score": 0.5,
                "anomaly_pct": 0.5,
                "flagged": False,
                "p_normal": 1.0,
                "p_benign_unusual": 0.0,
                "p_brute_force": 0.0,
                "p_botnet": 0.0,
                "predicted_class": "normal",
                "class_conf": 1.0,
                "verdict": "normal",
            }
            insert_scores([score])

            status = {
                "router_id": router_id,
                "ts": ts,
                "status": "healthy",
                "verdict": "normal",
                "anomaly_pct": 0.5,
                "open_incident_id": None,
            }
            upsert_status([status])

            incident = {
                "incident_id": incident_id,
                "router_id": router_id,
                "status": "open",
                "opened_ts": ts,
                "last_ts": ts,
                "closed_ts": None,
                "version": 1,
                "incident_type": "botnet",
                "severity": "high",
            }
            upsert_incident(incident)
            insert_truth(
                [{"router_id": router_id, "ts": ts, "label": "normal", "scenario": "normal", "phase": "none"}]
            )

            insert_command("selftest", router_id)
            command = pending_commands()[0]
            mark_command_done(command["id"])

            request_report(incident_id, 1)
            request = claim_report_request()
            if request != {"incident_id": incident_id, "version": 1}:
                raise RuntimeError("Report queue did not return the inserted request.")

            audit = {
                "incident_id": incident_id,
                "version": 1,
                "raw_snapshot": {"router_id": router_id},
                "sent_payload": {"incident_token": "INCIDENT_TEST"},
                "transformations": [],
                "token_map": {"ROUTER_TEST": router_id},
                "leak_check": {"passed": True, "found": []},
                "bytes_raw": 20,
                "bytes_sent": 30,
            }
            save_audit(audit)
            save_report(
                incident_id,
                1,
                "fallback",
                None,
                1,
                None,
                {"executive_summary": "Self-test report"},
            )
            finish_report_request(incident_id, 1, "done")

            if recent_records(router_id, 1) != [record]:
                raise RuntimeError("Raw record write/read failed.")
            if latest_score(router_id) is None:
                raise RuntimeError("Score write/read failed.")
            if router_ids() != [router_id] or not latest_status():
                raise RuntimeError("Router status write/read failed.")
            if get_incident(incident_id) != incident:
                raise RuntimeError("Incident write/read failed.")
            if latest_report(incident_id) is None or latest_audit(incident_id) is None:
                raise RuntimeError("Report or privacy audit write/read failed.")
            if pending_commands() or claim_report_request() is not None:
                raise RuntimeError("Completed queue items were returned as pending.")

            with connect() as connection:
                counts = {
                    table: connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in expected
                }
            empty_tables = [table for table, count in counts.items() if count == 0]
            if empty_tables:
                raise RuntimeError(f"Self-test did not write to: {empty_tables}")

            reset_db()
            with connect() as connection:
                remaining = sum(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in expected
                )
            if remaining:
                raise RuntimeError("Database reset did not clear all self-test rows.")
        finally:
            DB_PATH = original_path

    print("SQLite self-test passed; the live database was not changed.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="EdgeSentinel database setup")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="check database reads, writes, queue, and reset in a temporary file",
    )
    args = parser.parse_args()

    if args.selftest:
        selftest()
    else:
        init_db()
        print(f"Database initialized: {DB_PATH.resolve()}")
