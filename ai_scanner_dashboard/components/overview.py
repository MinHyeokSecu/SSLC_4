"""Pipeline, KPI, and chart components."""

from __future__ import annotations

import altair as alt
import streamlit as st

from models.schemas import ScanResult
from services.metrics import (
    PROCESS_LABELS,
    DashboardMetrics,
    category_counts,
    severity_comparison,
    severity_counts,
    verification_counts,
)


CHART_HEIGHT = 230
SEVERITY_DOMAIN = ["Critical", "High", "Medium", "Low"]
SEVERITY_RANGE = ["#B42318", "#E05D37", "#D4A72C", "#667085"]


def _short_time(value) -> str:
    return value.strftime("%m-%d %H:%M") if value else "처리 전"


def render_pipeline(scan: ScanResult) -> None:
    st.subheader("진단 흐름", anchor=False)
    with st.container(horizontal=True):
        for step in scan.pipeline.steps:
            error_text = "오류 없음" if not step.error else "오류 있음"
            st.metric(
                f"{step.label} · {error_text}",
                PROCESS_LABELS[step.status],
                f"{step.count}건 · {_short_time(step.last_processed_at)}",
                delta_color="off",
                border=True,
            )


def render_kpis(metrics: DashboardMetrics) -> None:
    st.subheader("핵심 지표", anchor=False)
    cards = [
        ("스캔 페이지", f"{metrics.scanned_pages}개"),
        ("전체 탐지", f"{metrics.total_findings}건"),
        ("검증 완료", f"{metrics.verified_findings}건"),
        ("오탐/제외", f"{metrics.false_positives}건"),
        ("Critical/High", f"{metrics.critical_high}건"),
        ("업로드 증적", f"{metrics.evidence_count}개"),
        ("최종 보고서", metrics.final_report_status),
    ]
    with st.container(horizontal=True):
        for label, value in cards:
            st.metric(label, value, border=True)


def _bar_chart(
    data,
    category: str,
    value: str,
    *,
    color: str = "#344054",
    horizontal: bool = False,
) -> alt.Chart:
    base = alt.Chart(data).mark_bar(cornerRadiusEnd=4)
    tooltip = [alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{value}:Q")]
    if horizontal:
        return base.encode(
            x=alt.X(f"{value}:Q", title=None, axis=alt.Axis(tickMinStep=1)),
            y=alt.Y(f"{category}:N", title=None, sort="-x"),
            color=alt.value(color),
            tooltip=tooltip,
        ).properties(height=CHART_HEIGHT)
    return base.encode(
        x=alt.X(f"{category}:N", title=None, sort=None),
        y=alt.Y(f"{value}:Q", title=None, axis=alt.Axis(tickMinStep=1)),
        color=alt.value(color),
        tooltip=tooltip,
    ).properties(height=CHART_HEIGHT)


def render_charts(scan: ScanResult) -> None:
    st.subheader("취약점 현황", anchor=False)
    first_row = st.columns(2)
    with first_row[0].container(border=True, height="stretch"):
        st.markdown("**유형별 탐지**")
        st.altair_chart(
            _bar_chart(
                category_counts(scan.findings),
                "취약점 유형",
                "탐지 건수",
                horizontal=True,
            )
        )

    with first_row[1].container(border=True, height="stretch"):
        st.markdown("**최종 위험도 분포**")
        severity_data = severity_counts(scan.findings)
        severity_chart = (
            alt.Chart(severity_data)
            .mark_bar(cornerRadiusEnd=4)
            .encode(
                x=alt.X("위험도:N", title=None, sort=SEVERITY_DOMAIN),
                y=alt.Y("탐지 건수:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                color=alt.Color(
                    "위험도:N",
                    scale=alt.Scale(domain=SEVERITY_DOMAIN, range=SEVERITY_RANGE),
                    legend=None,
                ),
                tooltip=["위험도:N", "탐지 건수:Q"],
            )
            .properties(height=CHART_HEIGHT)
        )
        st.altair_chart(severity_chart)

    second_row = st.columns(2)
    with second_row[0].container(border=True, height="stretch"):
        st.markdown("**검증 상태**")
        st.altair_chart(
            _bar_chart(
                verification_counts(scan.findings),
                "검증 상태",
                "탐지 건수",
                color="#475467",
                horizontal=True,
            )
        )

    with second_row[1].container(border=True, height="stretch"):
        st.markdown("**1차 판정과 최종 판정**")
        comparison = severity_comparison(scan.findings)
        comparison_chart = (
            alt.Chart(comparison)
            .mark_bar(cornerRadiusEnd=3)
            .encode(
                x=alt.X("위험도:N", title=None, sort=SEVERITY_DOMAIN),
                y=alt.Y("탐지 건수:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                xOffset="판정 시점:N",
                color=alt.Color(
                    "판정 시점:N",
                    title=None,
                    scale=alt.Scale(range=["#98A2B3", "#344054"]),
                    legend=alt.Legend(orient="bottom"),
                ),
                tooltip=["위험도:N", "판정 시점:N", "탐지 건수:Q"],
            )
            .properties(height=CHART_HEIGHT)
        )
        st.altair_chart(comparison_chart)
