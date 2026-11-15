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
    "critical": ("#c62828", "CRITICAL"),
}


st.set_page_config(
    page_title="EdgeSentinel",
    layout="wide",
)

# The engine normally creates the schema first. Calling this here as well means
# the dashboard can start by itself and show a useful empty state.
db.init_db()

st.title("EdgeSentinel | TDS fleet security")
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
        f'<div>Status: <span style="color:{color};font-weight:700">{label}</span></div>',
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


def _render_report(report_row: dict | None) -> None:
    st.subheader("Incident and investigation")
    if report_row is None:
        st.info("No saved report for this incident yet.")
        return

    source = report_row.get("source")
    if source == "openai":
        st.success("AI report")
    else:
        st.info("Template report")

    _render_report_body(report_row.get("report") or {})


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


def _render_privacy_panel(audit: dict | None) -> None:
    st.subheader("What the AI saw")
    if audit is None:
        st.info("No privacy audit is available for this incident yet.")
        return

    leak_check = audit.get("leak_check") or {}
    passed = leak_check.get("passed") is True
    blocked = leak_check.get("blocked") is True
    values_checked = leak_check.get("values_checked", "unknown")

    if passed and not blocked:
        st.success(f"Leak check passed · {values_checked} private values checked")
    else:
        st.error("Leak check did not pass. The payload must not be sent to an AI service.")

    payload_status = leak_check.get("payload_status")
    api_call_made = leak_check.get("api_call_made")
    if payload_status:
        st.caption(f"Payload status: {payload_status}; API call made: {api_call_made}")

    left, right = st.columns(2)
    with left:
        st.markdown("**Kept inside TDS · raw snapshot**")
        raw_snapshot = audit.get("raw_snapshot")
        if isinstance(raw_snapshot, (dict, list)):
            st.json(raw_snapshot)
        elif raw_snapshot is not None:
            st.code(str(raw_snapshot), language="json")
        else:
            st.caption("No raw snapshot saved.")

    with right:
        st.markdown("**Prepared payload for OpenAI**")
        sent_payload = audit.get("sent_payload")
        if isinstance(sent_payload, str):
            st.code(sent_payload, language="json")
        elif sent_payload is not None:
            st.json(sent_payload)
        else:
            st.caption("No payload saved.")

    transformations = audit.get("transformations")
    if transformations:
        st.markdown("**Transformations**")
        if isinstance(transformations, list):
            st.dataframe(pd.DataFrame(transformations), hide_index=True, use_container_width=True)
        else:
            st.json(transformations)

    found = leak_check.get("found") or []
    if found:
        st.error("The leak check found values in the prepared payload.")
        st.json(found)

    with st.expander("Internal token map · never sent to OpenAI"):
        st.json(audit.get("token_map") or {})


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

    incident = db.open_or_latest_incident(selected)
    if incident is None:
        st.info("No incident has been recorded for this router.")
        return

    st.markdown(
        f"**{incident['incident_id']}** · {incident['incident_type'].replace('_', ' ').title()} · "
        f"{incident['severity'].title()} · version {incident['version']}"
    )
    st.caption(
        f"Opened: {incident.get('opened_ts', 'unknown')} · "
        f"Last updated: {incident.get('last_ts', 'unknown')} · "
        f"Status: {incident.get('status', 'unknown')}"
    )

    left, right = st.columns([3, 2])
    with left:
        _render_report(db.latest_report(incident["incident_id"]))
    with right:
        _render_privacy_panel(db.latest_audit(incident["incident_id"]))


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

    if saved["display_wording_edited"]:
        st.info("Wording edited locally after agent review. This is not a new AI response or human approval.")
        for note in saved["display_edit_notes"]:
            st.caption(note)
        with st.expander("Original AI response before wording edits"):
            st.json(saved["original_report"])

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

    st.divider()
    st.caption("Ground truth is hidden during judging.")


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
