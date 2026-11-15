"""Live EdgeSentinel fleet dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

from app import db
from app.evaluation import render_evaluation
from app.report_export import ExportUnavailable, live_report_download, rehearsal_report_download
from detection import config as detection_config
from reporting import replay


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_PATH = PROJECT_ROOT / "models" / "eval_report.json"
CHART_SIGNALS = (
    "dns_failures",
    "new_domains",
    "outbound_conns",
    "failed_logins_wan",
)
CLASS_PROBABILITIES = (
    ("Normal", "p_normal"),
    ("Unusual but likely benign", "p_benign_unusual"),
    ("Password guessing", "p_brute_force"),
    ("Botnet", "p_botnet"),
)
STATUS_BADGES = {
    "healthy": ("#16803c", "HEALTHY"),
    "watch": ("#a87500", "WATCH"),
    "warning": ("#c45b00", "WARNING"),
    "critical": ("#c62828", "URGENT"),
}


st.set_page_config(
    page_title="BroadBand Insight",
    layout="wide",
)

# The engine normally creates the schema first. Calling this here as well means
# the dashboard can start by itself and show a useful empty state.
db.init_db()

st.title("BroadBand Insight | TDS fleet security")
st.caption("Live simulated router activity")

if "selected_router_id" not in st.session_state:
    st.session_state.selected_router_id = None


def _render_fleet_header() -> None:
    summary = db.fleet_summary()
    columns = st.columns(4)
    columns[0].metric("Routers monitored", summary["routers_monitored"])
    columns[1].metric("Open incidents", summary["open_incidents"])
    columns[2].metric(
        "Highest open severity",
        summary["highest_open_severity"] or "None",
    )
    columns[3].metric(
        "AI / template reports",
        f'{summary["ai_reports"]} / {summary["template_reports"]}',
    )


def _render_fleet_grid() -> list[dict]:
    routers = db.latest_status()
    st.subheader("Fleet")

    if not routers:
        st.info("No live router data yet. Start the engine to populate the fleet.")
        return []

    columns = st.columns(6)
    for index, router in enumerate(routers):
        router_id = router["router_id"]
        status = router.get("status") or "unknown"
        verdict = router.get("verdict") or "waiting for score"
        anomaly_pct = router.get("anomaly_pct")
        anomaly_text = (
            f"{anomaly_pct:.1%}"
            if isinstance(anomaly_pct, (int, float))
            else "not available"
        )

        with columns[index % len(columns)]:
            with st.container(border=True):
                st.markdown(f"**{router_id}**")
                _render_status_badge(status)
                severity = router.get("incident_severity")
                if severity:
                    st.caption(f"Incident severity: {severity.title()}")
                st.caption(f"Verdict: {verdict}")
                st.caption(f"Anomaly percentile: {anomaly_text}")
                if st.button(
                    "View router",
                    key=f"select-router-{router_id}",
                    use_container_width=True,
                ):
                    st.session_state.selected_router_id = router_id
    return routers


def _render_status_badge(status: str) -> None:
    """Show the four agreed fleet states with stable, readable colors."""
    color, label = STATUS_BADGES.get(status, ("#666666", "UNKNOWN"))
    st.markdown(
        f'<div>Fleet status: <span style="color:{color};font-weight:700">{label}</span></div>',
        unsafe_allow_html=True,
    )


def _render_router_chart(router_id: str) -> None:
    records = db.recent_records(router_id, 120)
    scores = db.recent_scores(router_id, 120)
    st.subheader(f"Recent activity · {router_id}")

    if not records:
        st.info("No router records are available yet.")
        return

    figure = make_subplots(
        rows=5,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.06,
        subplot_titles=(
            "Failed DNS lookups",
            "New domains",
            "Outgoing connections",
            "Failed logins from outside the home",
            "Anomaly percentile",
        ),
    )

    for row_number, signal in enumerate(CHART_SIGNALS, start=1):
        figure.add_trace(
            go.Scatter(
                x=[row.get("ts") for row in records],
                y=[row.get(signal, 0) or 0 for row in records],
                mode="lines",
                name=signal,
                line={"width": 2},
                showlegend=False,
            ),
            row=row_number,
            col=1,
        )

    if scores:
        figure.add_trace(
            go.Scatter(
                x=[row["ts"] for row in scores],
                y=[row.get("anomaly_pct") for row in scores],
                mode="lines",
                name="Anomaly percentile",
                line={"color": "#d62728", "width": 2},
                showlegend=False,
            ),
            row=5,
            col=1,
        )
        figure.add_hline(
            y=detection_config.THRESHOLDS["anomaly_pct"],
            line_dash="dash",
            line_color="#555555",
            row=5,
            col=1,
        )

    figure.update_yaxes(range=[0, 1], row=5, col=1)
    figure.update_layout(
        height=760,
        margin={"l": 20, "r": 20, "t": 55, "b": 20},
        hovermode="x unified",
    )
    st.plotly_chart(figure, use_container_width=True)


def _render_classifier(router_id: str) -> None:
    score = db.latest_score(router_id)
    st.subheader("Classifier")

    if score is None:
        st.info("No model score is available yet.")
        return

    names = [item[0] for item in CLASS_PROBABILITIES]
    values = [float(score.get(item[1]) or 0.0) for item in CLASS_PROBABILITIES]
    chart_data = pd.DataFrame({"Pattern": names, "Model vote share": values})
    figure = px.bar(
        chart_data,
        x="Model vote share",
        y="Pattern",
        orientation="h",
        range_x=[0, 1],
        text_auto=".0%",
    )
    figure.update_layout(
        height=300,
        margin={"l": 10, "r": 10, "t": 20, "b": 20},
        showlegend=False,
    )
    st.plotly_chart(figure, use_container_width=True)
    st.markdown(f"**Verdict:** {score.get('verdict', 'unknown').replace('_', ' ').title()}")
    st.caption(
        f"Top class: {score.get('predicted_class', 'unknown')} · "
        f"Vote share: {float(score.get('class_conf') or 0.0):.0%}"
    )
    st.caption("Classifier confidence is a share of model votes, not a calibrated probability.")


def _render_report(report_row: dict | None, audit: dict | None) -> None:
    st.subheader("Incident and investigation")
    if report_row is None:
        st.info("No saved report for this incident yet.")
        return

    source = report_row.get("source")
    if source == "openai":
        st.success("Live AI report")
    elif source == "fallback":
        st.info("Template report")
    else:
        st.warning("Unknown report source")

    _render_report_metadata(
        report_row["version"], report_row.get("model"), report_row.get("created_at"),
        report_row.get("latency_ms"),
    )
    st.caption("Human review: Pending")
    _render_report_download(live_report_download, "edgesentinel-live-report.json", report_row, audit)
    _render_report_body(report_row.get("report") or {})


def _render_report_metadata(version, model, created_at=None, latency_ms=None) -> None:
    latency = f"{latency_ms:,} ms" if latency_ms is not None else "Not recorded"
    created = created_at or "Not recorded"
    st.caption(
        f"Displayed report version: {version} · Model: {model or 'None'} · "
        f"Created: {created} · Generation latency: {latency}"
    )


def _render_report_download(builder, filename: str, *args) -> None:
    try:
        data = builder(*args)
    except ExportUnavailable as error:
        st.caption(f"Download unavailable. {error}")
        return

    st.download_button(
        "Download report and prepared payload",
        data=data,
        file_name=filename,
        mime="application/json",
        key=filename,
        on_click="ignore",
    )


def _render_report_body(report: dict) -> None:
    st.markdown(f"**Summary:** {report.get('executive_summary', 'Report summary unavailable.')}")
    st.markdown(
        f"**Severity:** {report.get('severity', 'unknown').title()} — "
        f"{report.get('severity_rationale', '')}"
    )

    evidence = report.get("evidence") or []
    if evidence:
        st.markdown("**Evidence**")
        st.dataframe(pd.DataFrame(evidence), hide_index=True, use_container_width=True)

    if report.get("behavior_explanation"):
        st.markdown("**What the behavior may mean**")
        st.write(report["behavior_explanation"])

    alternatives = report.get("alternative_explanations") or []
    if alternatives:
        with st.expander("Other possible explanations"):
            for alternative in alternatives:
                st.markdown(f"**{alternative.get('explanation', 'Alternative')}**")
                st.write(alternative.get("why_less_likely", ""))
                st.caption(alternative.get("what_would_confirm_it", ""))

    customer_column, tds_column = st.columns(2)
    with customer_column:
        st.markdown("**Customer steps**")
        for action in report.get("customer_actions", []):
            st.markdown(f"- {action}")
    with tds_column:
        st.markdown("**TDS analyst steps**")
        for action in report.get("tds_actions", []):
            st.markdown(f"- {action}")

    with st.expander("Uncertainty and verification"):
        for note in report.get("uncertainty_and_limitations", []):
            st.markdown(f"- {note}")
        st.markdown("**Human verification steps**")
        for step in report.get("human_verification_steps", []):
            st.markdown(f"- {step}")

    if report.get("customer_message"):
        st.info(f"Customer message: {report['customer_message']}")


def _render_privacy_panel(audit: dict | None, report: dict | None = None) -> None:
    st.subheader("AI & Privacy")
    if audit is None:
        st.info("A matching privacy audit will appear here when available.")
        return

    leak_check = audit.get("leak_check") or {}
    passed = leak_check.get("passed") is True
    blocked = leak_check.get("blocked") is True
    if blocked:
        st.error("Privacy check blocked the request")
    elif passed:
        st.success("Privacy check passed")
    else:
        st.warning("Privacy check not confirmed")

    status_text = {
        "prepared_not_sent": "Prepared locally · not sent",
        "dispatch_pending": "Dispatch pending",
        "request_attempted": "AI request attempted",
    }.get(leak_check.get("payload_status"), "Dispatch status unavailable")
    st.caption(f"Report version: {audit['version']} · {status_text}")

    prepared = audit.get("sent_payload")
    payload = prepared
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            payload = None
    source = "Unavailable"
    if report is not None and (
        report.get("version") == audit.get("version")
        and report.get("incident_id") == audit.get("incident_id")
    ):
        if report.get("source") == "openai":
            source = f"OpenAI · {report.get('model') or 'model unavailable'}"
        elif report.get("source") == "fallback":
            source = "Local template"
    token = "Unavailable"
    input_summary = "Unavailable"
    if isinstance(payload, dict):
        # Only display the expected public token, never an unexpected identity.
        if payload.get("router_token") == "ROUTER_A":
            token = "ROUTER_A"
        evidence = payload.get("evidence")
        count = len(evidence) if isinstance(evidence, list) else 0
        input_summary = f"{count} measurements + detector context"
    else:
        st.warning("AI input is missing or unreadable.")
    check = "Blocked" if blocked else ("Passed" if passed else "Not confirmed")
    st.table(pd.DataFrame([
        {"": "Report source", "This report": source},
        {"": "Router reference", "This report": token},
        {"": "Privacy check", "This report": check},
        {"": "AI input", "This report": input_summary},
    ]).set_index(""))
    st.caption("Filter rules exclude customer identities and actual browsing destinations.")

    with st.expander("Show full AI input (payload)", expanded=False):
        st.caption("The saved input prepared for this report. No new AI request is made here.")
        if isinstance(payload, dict):
            # A formatted code block is readable and copyable without opening
            # dozens of nodes in Streamlit's JSON tree. Preserve every field.
            st.code(json.dumps(payload, ensure_ascii=False, indent=2), language="json")
        elif prepared is not None:
            st.code(str(prepared), language="json")
        else:
            st.caption("No prepared input saved.")

    with st.expander("Internal audit details", expanded=False):
        st.caption("This audit matches the displayed report version. A passed leak check "
                   "is a targeted safeguard, not a guarantee of anonymity. A request "
                   "attempt does not prove delivery or a successful AI report; check "
                   "the report source badge. Internal data below stays local.")
        st.markdown("**Internal snapshot at report generation**")
        raw = audit.get("raw_snapshot")
        if isinstance(raw, (dict, list)):
            st.json(raw)
        elif raw is not None:
            st.code(str(raw), language="json")
        else:
            st.caption("No raw snapshot saved.")
        st.markdown("**Filter transformations**")
        st.json(audit.get("transformations") or [])
        st.markdown("**Private token mapping**")
        st.json(audit.get("token_map") or {})
        st.markdown("**Privacy check details**")
        st.json(leak_check)


def _render_report_progress(view: db.InvestigationView) -> None:
    current = view.incident["version"]
    shown = view.report["version"] if view.report is not None else None
    if shown == current:
        return

    status = {
        "pending": "is pending",
        "in_progress": "is processing",
        "failed": "failed",
        "done": "is unavailable",
    }.get(view.queue_status, "has not been queued")
    message = f"Report for incident version {current} {status}."
    if shown is not None:
        message += f" Showing report version {shown}."
    if view.queue_status in {"failed", "done"}:
        st.warning(message)
    else:
        st.info(message)


def _render_live_tab() -> None:
    _render_fleet_header()
    routers = _render_fleet_grid()

    router_ids = [row["router_id"] for row in routers]
    if not router_ids:
        return

    if st.session_state.selected_router_id not in router_ids:
        st.session_state.selected_router_id = (
            "R-107" if "R-107" in router_ids else router_ids[0]
        )

    selected = st.session_state.selected_router_id
    st.divider()

    left, right = st.columns([3, 2])
    with left:
        _render_router_chart(selected)
    with right:
        _render_classifier(selected)

    view = db.investigation_view(selected)
    if view is None:
        st.info("No incident has been recorded for this router.")
        return

    incident = view.incident
    st.markdown(
        f"**{incident['incident_id']}** · {incident['incident_type'].replace('_', ' ').title()} · "
        f"Severity: {incident['severity'].title()} · Current incident version: {incident['version']}"
    )
    st.caption(
        f"Opened: {incident.get('opened_ts', 'unknown')} · "
        f"Last updated: {incident.get('last_ts', 'unknown')} · "
        f"Status: {incident.get('status', 'unknown')}"
    )
    _render_report_progress(view)

    left, right = st.columns([3, 2])
    with left:
        _render_report(view.report, view.audit)
    with right:
        _render_privacy_panel(view.audit, view.report)


@st.cache_data(ttl=5)
def _load_evaluation(path_text: str) -> dict:
    path = Path(path_text)
    return json.loads(path.read_text(encoding="utf-8"))


def _render_evaluation_tab() -> None:
    st.subheader("Evaluation")
    if not EVALUATION_PATH.exists():
        st.info("Evaluation results are not available yet.")
        return

    try:
        evaluation = _load_evaluation(str(EVALUATION_PATH))
    except (OSError, json.JSONDecodeError) as error:
        st.error(f"Could not read the evaluation file: {type(error).__name__}")
        return

    render_evaluation(evaluation)


def _render_saved_rehearsal_tab() -> None:
    st.subheader("Saved rehearsal")
    st.caption("Browse previously generated reports from synthetic rehearsal scenarios.")
    scenario = st.selectbox(
        "Saved scenario",
        replay.SCENARIOS,
        format_func=lambda value: value.replace("_", " ").capitalize(),
        key="saved-rehearsal-scenario",
    )
    try:
        saved = replay.load_saved_report(scenario).display_data()
    except replay.RehearsalUnavailable:
        st.warning("This saved report is unavailable. Choose another scenario.")
        return

    st.success(saved["badge"])
    st.caption(
        f"Original source: {saved['original_source']} · "
        f"Original model: {saved['model']} · "
        f"Human review: {saved['human_review'].replace('_', ' ').capitalize()}"
    )
    st.caption(f"API calls made by this viewer: {saved['api_requests_attempted']}")
    for note in saved["known_notes"]:
        st.warning(note)

    if "display_wording_edited" not in saved:
        st.warning("Viewer modules are from different versions. Restart the dashboard to load reviewed wording.")
    if saved.get("display_wording_edited", False):
        st.info("Wording edited locally after agent review. This is not a new AI response or human approval.")
        for note in saved["display_edit_notes"]:
            st.caption(note)
        with st.expander("Original AI response before wording edits"):
            st.json(saved["original_report"])

    _render_report_metadata(saved["payload"].get("report_version"), saved["model"])
    _render_report_download(rehearsal_report_download, "edgesentinel-saved-rehearsal.json", saved)
    _render_report_body(saved["report"])
    with st.expander("Saved rehearsal payload"):
        st.json(saved["payload"])


with st.sidebar:
    st.header("Demo controls")
    available_router_ids = db.router_ids()
    if available_router_ids:
        current = st.session_state.selected_router_id
        default_index = (
            available_router_ids.index(current)
            if current in available_router_ids
            else available_router_ids.index("R-107")
            if "R-107" in available_router_ids
            else 0
        )
        selected_router_id = st.selectbox(
            "Router",
            options=available_router_ids,
            index=default_index,
        )
        st.session_state.selected_router_id = selected_router_id

        commands = (
            ("Botnet", "botnet"),
            ("Start loud phase", "botnet_loud"),
            ("Fast password guessing", "brute_force_fast"),
            ("Slow password guessing", "brute_force_slow"),
            ("New smart device", "new_device"),
            ("Forgot password", "forgot_password"),
        )
        for label, command in commands:
            if st.button(label, use_container_width=True):
                db.insert_command(command, selected_router_id)
                st.success(f"Queued {label} for {selected_router_id}.")

        if st.button("Reset fleet", use_container_width=True):
            db.insert_command("reset", None)
            st.success("Queued fleet reset.")
    else:
        st.caption("Scenario controls appear after the engine publishes router IDs.")


live_tab, evaluation_tab, rehearsal_tab = st.tabs(["Live", "Evaluation", "Saved rehearsal"])
with live_tab:
    @st.fragment(run_every="2s")
    def live_view():
        _render_live_tab()

    live_view()

with evaluation_tab:
    _render_evaluation_tab()

with rehearsal_tab:
    _render_saved_rehearsal_tab()
