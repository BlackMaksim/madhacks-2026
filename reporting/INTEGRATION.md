# Maksym reporting: handoff to Person 4

The reporter now supports privacy, a bounded Luna call, validation, and template
fallback. All development checks use mocks or the in-memory example; SQLite
integration is not verified until `app/db.py` exists.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m reporting.reporter --example
```

This example always forces offline mode. `--example --send` explicitly permits
one paid synthetic request and limits that process to one request. Without
`--example`, the worker loads root `.env` (exported environment variables take
precedence), so keep `DEMO_OFFLINE=1` until live calls are intended.

## Required `app.db` interface

The signatures follow blueprint section 9:

- `claim_report_request()` atomically claims one row, returning `incident_id` and
  integer `version`, or `None`.
- `get_incident(incident_id)` returns the incident dictionary, including `version`.
- `recent_records(router_id, minutes)` returns raw record dictionaries. The worker
  requests 30 simulated minutes; this must not be a wall-clock filter.
- `save_audit(audit)` **upserts** by `(incident_id, version)`. The same audit row
  is saved before dispatch and updated afterward. Serialize the structured
  `raw_snapshot`, `transformations`, `token_map`, and `leak_check` fields to JSON.
  `sent_payload` is already an exact serialized JSON string; do not serialize
  it a second time. Keep raw snapshots and token maps internal.
- `save_report(incident_id, version, source, model, latency_ms, error, report)`
  upserts a report dictionary under the same key. Sources are `openai` and
  `fallback`. `model` is `None` when the displayed report is a template.
- `finish_report_request(incident_id, version, status)` sets `done` or `failed`.

All connections must release write transactions before model/network work.
The reporter must not hold a SQLite write lock during a request.

## Audit display semantics

`leak_check.payload_status` distinguishes:

- `prepared_not_sent`: offline, blocked, missing key, or another preflight guard.
- `dispatch_pending`: intent persisted; dispatch/delivery is uncertain if the
  process stops here.
- `request_attempted`: the SDK request was attempted; this is not proof of
  successful delivery or of a valid AI report.

The legacy `bytes_sent` field counts prepared payload bytes, not network bytes.
Use `reports.source` and its error alongside audit state. Do not label an offline
payload as actually sent to OpenAI. A leak can appear only in the internal audit;
do not copy its values into error banners or generic application logs.

## Budget and unresolved DB integration

One `ReportWriter` is shared for the entire reporter process. Default local
settings use Luna, 20 attempted requests per process (configurable up to 60),
three attempts per incident, and no repeated attempt for the same version in
that process. SDK retries are zero; each response is capped at 2,000 output tokens.
Timeouts and API failures consume an attempt. These limits reset on restart and
are not a durable dollar budget. API smoke tests are separate processes.

An old queue version is currently marked failed if `get_incident` returns a newer
version; it is never silently relabeled. We still need an agreed version-snapshot
interface for reliable escalation/backlog processing. We also still need DB-owned
claim timestamps/leases and recovery of stale `in_progress` requests. Report
upserts prevent duplicate displayed rows but cannot guarantee exactly-once paid
requests across a crash/restart. No reset or schema migration is performed by the
reporter.

## Escalation context

Within the shared `ReportWriter`, the latest allowlisted measurement payload is
cached by `(incident_id, router_id)`. Versions 2 and 3 receive an additive
`previous_summary` object containing only validated codes, flags, and numeric
evidence. No previous AI prose, customer identity, timestamps, or raw records are
copied into this field. Version 1 retains its existing payload shape.

The local template and AI prompt explain changes relative to the last available
snapshot, including high-to-critical severity changes. If history is absent after
restart, `previous_summary.available` is false and the report must disclose that
previous context is unavailable. The worker does not invent a missing version.
The comparison cache is not durable and does not solve the separate issue of
retrieving an old queued incident version from `get_incident`.

Offline rehearsal, with no credentials or API requests:

```powershell
.\.venv\Scripts\python.exe -m reporting.escalation_check
```
