# Maksym reporting: handoff to Person 4

## Historical report wording

Replay preserves original response files, hashes, payloads and the pending human
review status. `display_data()` applies explicit local wording edits to three
historical reports, with `display_wording_edited`, `display_edit_notes`, and
`original_report` metadata. The dashboard labels these edits and exposes the
original response separately. They are not new AI generations or human approval.
`success_after_failures` is a legacy co-occurrence flag; it does not establish
event order, the successful sign-in's origin, or unauthorized access. Current
prompts and payload limitations state this explicitly.

## Login-source units (AI input v2)

New payloads use `schema_version: ai_input_v2`. Their login summary replaces
`distinct_outside_sources_10min` with `summed_login_sources_10min`, computed
from raw `login_sources` counters in the supplied last-ten-minute window.
A source seen in ten minutes can contribute ten to this sum. It does not
establish the number of unique external sources; incomplete records also
do not establish a complete ten-minute total. The detector's incident contract
is unchanged. Do not relabel its legacy `distinct_outside_sources_10min` value
as an exact unique-source count in other views.

Historical rehearsal artifacts keep their original payloads and hashes.
They remain available through replay; matching a newly prepared v2 payload
against an old saved v1 payload must fail rather than substitute an old report.

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

Engine startup seeds `IncidentManager` with `db.next_incident_number()`, above
numeric IDs retained in incidents, queue, reports, and audit. This prevents
pre-restart reports or completed queue keys being reused for a new incident.
It assumes one engine process. It does not restore the simulator clock or
the manager's open/closed incident state after a restart.

The signatures follow blueprint section 9:

- `claim_report_request()` atomically claims one row, returning `incident_id` and
  integer `version`, or `None`.
- `get_incident(incident_id)` returns the incident dictionary, including `version`.
- `recent_records(router_id, minutes)` returns raw record dictionaries. The worker
  uses this interface for the in-memory example and older adapters.
- The SQLite adapter also supplies `get_report_inputs(incident_id, version)`.
  It returns the incident snapshot saved when the engine queued that version and
  up to 30 readings ending at the snapshot's simulated timestamp.
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

The SQLite adapter adds a snapshot column when the reporter initializes the
database. Queue entries created before that upgrade can use the current incident
only if its version still matches the request. A second migration adds
`claimed_at`, a real UTC timestamp distinct from simulated incident time.
Each queue poll atomically recovers `in_progress` claims at least two real
minutes old. A fresh claim is left alone; a stale claim with an existing report
becomes `done`, while one without a report returns to `pending` for retry.
Legacy rows without claim timestamps use `requested_at`; rows with neither
timestamp are recoverable immediately. Finished and failed rows are unchanged.
Recovery runs on later polls too, so restarting before expiry does not leave
the claim stuck forever. The SQLite write lock ends before model/network work.

This demo assumes a single reporter and SDK calls bounded by the 30-second
timeout, below the two-minute claim lifetime. There is no heartbeat or fencing
for a worker paused longer than that lifetime. Report upserts prevent duplicate
displayed rows but cannot guarantee exactly-once paid requests across a crash
after dispatch and before saving its result. Prefer offline mode for crash tests.

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

## Injection rehearsal

```powershell
.\.venv\Scripts\python.exe -m reporting.injection_check
```

This uses a synthetic R-104 in-memory incident. The instruction-like device name
is retained in the raw internal audit and absent from the prepared payload. A
second request deliberately contaminates the prepared payload with a private
value and must return a template with `privacy_check_blocked` before client
creation. The rehearsal does not read `.env`; its client factory forbids network
access even if the privacy gate regresses. Its scoped fault patch is restored
before returning. This is not yet the running Fleet → SQLite → dashboard demo.

## Saved reports for an offline demonstration

```powershell
.\.venv\Scripts\python.exe -m reporting.replay --list
.\.venv\Scripts\python.exe -m reporting.replay --scenario botnet_quiet
```

This viewer has no API, `.env`, or database dependency. It selects four examples
from `luna_v1` and the two corrected brute-force examples from
`luna_v2_bruteforce`, checks repository-manifest hashes, and revalidates each
report locally. Old brute-force v1 reports are not selected. The known minor
incident-token wording issue in the saved loud report is displayed as a note.

For the dashboard, use `reporting.replay.load_saved_report(scenario).display_data()`
in an explicitly separate saved-example view. Preserve `source=saved_rehearsal`,
`original_source=openai`, and the **Saved from rehearsal** badge beside the report.
The provider is the original generator, not a live call. Human-review status is
still pending; the agent's review is not a human security approval.

Do not attach a saved example to a new live incident just because its category
or severity matches. If a caller supplies `expected_payload`, every prepared
payload value must match the saved one exactly or the loader refuses it. The
normal offline reporter continues using a fresh template for current incidents.
No saved example is inserted into SQLite by this module, and no `reports.source`
contract or dashboard UI has been changed automatically.
