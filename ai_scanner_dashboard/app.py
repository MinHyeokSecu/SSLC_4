"""AI Scanner security assessment dashboard."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from components.evidence import render_evidence_upload
from components.findings import render_finding_detail, render_findings_table
from components.overview import render_charts, render_kpis, render_pipeline
from components.reports import render_reports
from providers import ProviderError, create_provider
from services.metrics import compute_dashboard_metrics
from settings import Settings, load_settings


st.set_page_config(
    page_title="AI Scanner dashboard",
    page_icon=":material/security:",
    layout="wide",
)


@st.cache_data(ttl="5m", max_entries=4, show_spinner="진단 데이터를 불러오는 중입니다...")
def load_scan_data(
    provider_name: str,
    mock_data_path: str,
    api_url: str | None,
    result_path: str | None,
    model_name: str | None,
    max_upload_mb: int,
):
    """Load normalized source data while keeping cheap UI filters uncached."""
    runtime_settings = Settings(
        provider=provider_name,
        mock_data_path=Path(mock_data_path),
        tool_api_url=api_url,
        tool_result_path=Path(result_path) if result_path else None,
        tool_model_name=model_name,
        max_upload_mb=max_upload_mb,
    )
    return create_provider(runtime_settings).get_scan_result()


def clear_dashboard_cache() -> None:
    load_scan_data.clear()


st.session_state.setdefault("session_evidence", [])

try:
    settings = load_settings()
    provider = create_provider(settings)
    scan = load_scan_data(
        settings.provider,
        str(settings.mock_data_path),
        settings.tool_api_url,
        str(settings.tool_result_path) if settings.tool_result_path else None,
        settings.tool_model_name,
        settings.max_upload_mb,
    )
except (ProviderError, ValueError) as exc:
    st.error(f"대시보드 데이터를 불러오지 못했습니다. {exc}", icon=":material/error:")
    st.caption("설정과 JSON 스키마를 확인한 뒤 새로고침해 주세요.")
    st.stop()

st.logo(":material/security:", size="large")
with st.sidebar:
    st.markdown("### AI Scanner")
    st.badge(provider.source_label, color="gray", icon=":material/database:")
    st.caption(f"스캔 ID · {scan.scan_id}")
    st.caption(f"대상 · {scan.target.name}")
    st.button(
        "데이터 새로고침",
        icon=":material/refresh:",
        on_click=clear_dashboard_cache,
        width="stretch",
    )
    st.caption("실제 스캔·공격·API 호출 없음")

with st.container(
    horizontal=True,
    horizontal_alignment="distribute",
    vertical_alignment="center",
):
    st.title("AI Scanner 보안 진단", anchor=False)
    st.badge(provider.source_label, color="gray", icon=":material/science:")
st.caption(f"{scan.target.name} · {scan.target.base_url}")

render_pipeline(scan)
metrics = compute_dashboard_metrics(scan, len(st.session_state.session_evidence))
render_kpis(metrics)
render_charts(scan)

selected_finding = render_findings_table(scan.findings)
if selected_finding:
    render_finding_detail(selected_finding, scan.evidence)

st.subheader("증적 및 보고서", anchor=False)
bottom = st.columns([1.2, 0.8], vertical_alignment="top")
with bottom[0]:
    render_evidence_upload(scan.findings, settings.max_upload_mb)
with bottom[1]:
    render_reports(scan.reports)

st.caption(
    "모의 데이터 기반 화면 · 업로드 파일은 현재 세션 메모리에만 보관 · 실제 AI 연동 전"
)
