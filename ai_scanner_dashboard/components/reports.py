"""Compact report generation status and preview."""

from __future__ import annotations

import streamlit as st

from models.schemas import Report
from services.metrics import PROCESS_LABELS


REPORT_COLORS = {
    "pending": "gray",
    "running": "blue",
    "completed": "green",
    "error": "red",
}


def render_reports(reports: list[Report]) -> None:
    with st.container(border=True):
        st.markdown("**보고서 생성 현황**")
        for report in reports:
            with st.container(
                horizontal=True,
                horizontal_alignment="distribute",
                vertical_alignment="center",
            ):
                st.write(report.name)
                st.badge(
                    PROCESS_LABELS[report.status],
                    color=REPORT_COLORS[report.status],
                )

        selected_id = st.selectbox(
            "미리보기",
            options=[report.report_id for report in reports],
            format_func=lambda report_id: next(
                report.name for report in reports if report.report_id == report_id
            ),
            key="report_preview",
        )
        selected = next(report for report in reports if report.report_id == selected_id)
        st.caption(selected.summary)
        st.button(
            "실제 생성 기능 연결 전",
            icon=":material/description:",
            disabled=True,
            width="stretch",
        )
