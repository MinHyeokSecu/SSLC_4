"""Finding filter, table selection, and detail components."""

from __future__ import annotations

import streamlit as st

from models.schemas import Evidence, Finding
from services.metrics import STATUS_LABELS, findings_frame


SEVERITY_COLORS = {
    "Critical": "red",
    "High": "orange",
    "Medium": "yellow",
    "Low": "gray",
}
STATUS_COLORS = {
    "unverified": "gray",
    "verified": "green",
    "false_positive": "blue",
    "reanalysis_required": "orange",
}


def _filter_findings(findings: list[Finding]) -> list[Finding]:
    with st.popover("필터", icon=":material/filter_list:"):
        categories = st.multiselect(
            "취약점 유형",
            options=["SQL Injection", "XSS", "File Upload"],
            default=["SQL Injection", "XSS", "File Upload"],
            key="filter_categories",
        )
        severities = st.multiselect(
            "최종 위험도",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
            key="filter_severities",
        )
        statuses = st.multiselect(
            "검증 상태",
            options=list(STATUS_LABELS),
            default=list(STATUS_LABELS),
            format_func=lambda value: STATUS_LABELS[value],
            key="filter_statuses",
        )
        evidence_filter = st.segmented_control(
            "증적 유무",
            options=["전체", "있음", "없음"],
            default="전체",
            required=True,
            key="filter_evidence",
        )

    filtered = [
        item
        for item in findings
        if item.category in categories
        and item.final_severity in severities
        and item.verification_status in statuses
    ]
    if evidence_filter == "있음":
        filtered = [item for item in filtered if item.evidence_ids]
    elif evidence_filter == "없음":
        filtered = [item for item in filtered if not item.evidence_ids]
    return filtered


def render_findings_table(findings: list[Finding]) -> Finding | None:
    with st.container(
        horizontal=True,
        horizontal_alignment="distribute",
        vertical_alignment="center",
    ):
        st.subheader("취약점 목록", anchor=False)
        filtered = _filter_findings(findings)

    st.caption(f"{len(filtered)}건 표시 · 행을 선택하면 상세 정보를 확인할 수 있습니다.")
    if not filtered:
        st.info("현재 필터에 맞는 취약점이 없습니다.", icon=":material/search_off:")
        return None

    table = findings_frame(filtered)
    event = st.dataframe(
        table,
        key="findings_table",
        hide_index=True,
        height=350,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "취약점 ID": st.column_config.TextColumn(pinned=True),
            "신뢰도": st.column_config.ProgressColumn(
                min_value=0,
                max_value=1,
                format="percent",
            ),
            "마지막 분석": st.column_config.DatetimeColumn(
                format="MM-DD HH:mm"
            ),
        },
    )
    selected_rows = event.selection.rows
    if not selected_rows:
        return None
    return filtered[selected_rows[0]]


def render_finding_detail(finding: Finding, evidence: list[Evidence]) -> None:
    with st.container(border=True):
        with st.container(
            horizontal=True,
            horizontal_alignment="distribute",
            vertical_alignment="center",
        ):
            st.markdown(f"### {finding.finding_id} · {finding.category}")
            with st.container(horizontal=True, vertical_alignment="center"):
                st.badge(
                    finding.final_severity,
                    color=SEVERITY_COLORS[finding.final_severity],
                )
                st.badge(
                    STATUS_LABELS[finding.verification_status],
                    color=STATUS_COLORS[finding.verification_status],
                )

        with st.container(horizontal=True):
            st.metric("대상", finding.url, border=True)
            st.metric("파라미터", finding.parameter, border=True)
            st.metric("CVSS", f"{finding.cvss:.1f}" if finding.cvss else "-")
            st.metric("신뢰도", f"{finding.confidence:.0%}")

        st.write(finding.summary)
        decision_tab, http_tab, action_tab, coding_tab = st.tabs(
            ["판정", "HTTP 요약", "영향 및 개선", "시큐어코딩"]
        )
        with decision_tab:
            st.markdown(f"**1차 자동 판정**  \n{finding.initial_assessment}")
            st.markdown(f"**담당자 검증**  \n{finding.analyst_verification}")
            st.markdown(f"**AI 재분석**  \n{finding.ai_reanalysis}")
            st.caption("탐지 근거")
            st.code(finding.detection_basis, language=None, wrap_lines=True)

        with http_tab:
            st.caption("요청 요약")
            st.code(finding.http_request_summary, language=None, wrap_lines=True)
            st.caption("응답 요약")
            st.code(finding.http_response_summary, language=None, wrap_lines=True)

        with action_tab:
            with st.container(horizontal=True):
                st.metric("CWE", finding.cwe or "-")
                st.metric("CVE", finding.cve or "해당 없음")
                st.metric("CVSS", f"{finding.cvss:.1f}" if finding.cvss else "-")
            st.markdown(f"**영향도**  \n{finding.impact}")
            st.markdown(f"**개선 방안**  \n{finding.remediation}")

        with coding_tab:
            st.info(finding.secure_coding, icon=":material/code:")

        linked = [item for item in evidence if item.evidence_id in finding.evidence_ids]
        session_linked = [
            item
            for item in st.session_state.get("session_evidence", [])
            if item["finding_id"] == finding.finding_id
        ]
        st.markdown("**연결된 증적**")
        if linked or session_linked:
            rows = [
                {
                    "증적 ID": item.evidence_id,
                    "파일명": item.filename,
                    "유형": item.type,
                    "크기": item.size_bytes,
                    "업로드 시각": item.uploaded_at,
                }
                for item in linked
            ]
            rows.extend(
                {
                    "증적 ID": item["evidence_id"],
                    "파일명": item["filename"],
                    "유형": "session_upload",
                    "크기": item["size_bytes"],
                    "업로드 시각": None,
                }
                for item in session_linked
            )
            st.dataframe(
                rows,
                hide_index=True,
                column_config={
                    "크기": st.column_config.NumberColumn(format="%d bytes"),
                    "업로드 시각": st.column_config.DatetimeColumn(
                        format="MM-DD HH:mm"
                    ),
                },
            )
        else:
            st.caption("연결된 증적이 없습니다.")
