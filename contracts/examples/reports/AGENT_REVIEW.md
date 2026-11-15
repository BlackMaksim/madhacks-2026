# Agent review of Luna rehearsal v1

Reviewed the six saved `luna_v1` reports against their saved payloads. This is an
agent assessment, not a human security sign-off. Original generated JSON and its
`human_review: pending` labels are preserved. No new API calls were made by this review.

The run completed six API requests and reported 7,400 input and 4,720 output tokens.
All six reports passed the original automatic checks with no generation warnings.
These are hand-authored reporting fixtures, not measured detector predictions or
an estimate of real-world detection accuracy.

| Scenario | Assessment | Findings |
| --- | --- | --- |
| botnet_quiet | Acceptable for prototype rehearsal, human review pending | Evidence values match; does not assert an established infection or invent a traffic flood. Customer guidance asks for support before disruptive changes. |
| botnet_loud | Acceptable with minor usability note | Critical severity and evidence values match; isolation requires human verification. Asking the customer to share the local incident token is not useful because `INCIDENT_1` is not a customer-facing support reference. Prompt updated for future reports. |
| brute_force_fast | Needs revision | `login_sources=10` is a sum of minute-level distinct counts, but the report describes it as a distinct-source count. The actual window-level outside-source count is 2. This ambiguity originated in our payload's meaning text. No successful intrusion is asserted. |
| brute_force_slow_success | Needs revision | Same ambiguous description of the summed `login_sources` signal. The window-level distinct count happens to be 10 here, hiding the unit problem. The successful-login flag is correctly treated as a reason to investigate, not proof of unauthorized access. |
| new_device | Acceptable for prototype rehearsal, human review pending | Low-severity benign category is retained. New-device context is mentioned without claiming causation or recommending blind disconnection. |
| unknown_anomaly | Acceptable for prototype rehearsal, human review pending | Keeps the cause unknown and does not force an attack label; explains that classifier confidence is not calibrated probability. |

Corrections: clarify `login_sources` as a sum of per-minute counts; explain that
the same source may repeat across minutes; use `login_summary` for interval-level
distinct outside sources. Add a business-rule regression check and make fallback
wording explicit too. Rehearse only the two affected brute-force scenarios in a
NEW directory; keep v1 outputs as historical evidence rather than editing AI text
to appear generated correctly.

Limits: the original numeric/schema checks did not catch this semantic issue.
The new wording check is targeted and does not prove every natural-language claim
is correct. Human review, escalation history, and real SQLite integration remain
separate tasks.

## Brute-force v2 follow-up

Reviewed both generated reports in `luna_v2_bruteforce` against their saved
payloads. The follow-up used two requests, reporting 2,686 input and 1,562 output
tokens. Both passed automatic checks with no generation warnings.

- Fast guessing: the report now explicitly calls 10 a summed per-minute count,
  explains repeated sources across minutes, and separately identifies the two
  distinct outside sources over ten minutes. Medium severity is preserved; it
  does not assert a successful intrusion.
- Slow guessing with a success: the report makes the same distinction, separately
  reports ten distinct outside sources, preserves high severity, and asks for
  verification of whether the successful login was authorized.

The targeted aggregation issue is resolved in these two observed outputs. For
the current prototype examples, use the four non-brute-force reports from
`luna_v1` and the two brute-force reports from `luna_v2_bruteforce`. The original
v1 brute-force reports remain historical examples of the issue, not approved
rehearsal text. The minor v1 loud-report request to share a local incident token
remains a known usability limitation; the prompt has been corrected for future
generations without spending another request just for that wording.

This completes the agent's six-scenario prototype reporting review with that
minor limitation. It does not complete human review, detector evaluation,
escalation-history support, offline playback integration, or SQLite integration.
No `human_review` field has been changed to imply a human approved these outputs.
