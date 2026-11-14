"""Live EdgeSentinel fleet dashboard."""

import streamlit as st

from app import db


st.set_page_config(
    page_title="EdgeSentinel",
    page_icon="🛡️",
    layout="wide",
)

st.title("EdgeSentinel · TDS fleet security")
st.caption("Live simulated router activity")


if "selected_router_id" not in st.session_state:
    st.session_state.selected_router_id = None


@st.fragment(run_every="2s")
def live_fleet():
    """Refresh the fleet summary and router tiles every two seconds."""
    summary = db.fleet_summary()

    metric_columns = st.columns(4)
    metric_columns[0].metric(
        "Routers monitored",
        summary["routers_monitored"],
    )
    metric_columns[1].metric(
        "Open incidents",
        summary["open_incidents"],
    )
    metric_columns[2].metric(
        "Highest open severity",
        summary["highest_open_severity"] or "None",
    )
    metric_columns[3].metric(
        "AI / template reports",
        f'{summary["ai_reports"]} / {summary["template_reports"]}',
    )

    st.subheader("Fleet")

    routers = db.latest_status()

    if not routers:
        st.info(
            "No live router data yet. Start the engine to populate the fleet."
        )
        return

    tile_columns = st.columns(6)

    for index, router in enumerate(routers):
        router_id = router["router_id"]
        status = router.get("status") or "unknown"
        verdict = router.get("verdict") or "waiting for score"
        anomaly_pct = router.get("anomaly_pct")

        if isinstance(anomaly_pct, (int, float)):
            anomaly_text = f"{anomaly_pct:.1%}"
        else:
            anomaly_text = "n/a"

        with tile_columns[index % 6]:
            with st.container(border=True):
                st.markdown(f"**{router_id}**")
                st.write(f"Status: {status}")
                st.caption(f"Verdict: {verdict}")
                st.caption(f"Anomaly percentile: {anomaly_text}")

                if st.button(
                    "Select router",
                    key=f"select-{router_id}",
                    use_container_width=True,
                ):
                    st.session_state.selected_router_id = router_id

    selected = st.session_state.selected_router_id

    if selected:
        st.info(f"Selected router: {selected}")
    else:
        st.caption("Select a router tile to choose it for the detail view.")


live_fleet()