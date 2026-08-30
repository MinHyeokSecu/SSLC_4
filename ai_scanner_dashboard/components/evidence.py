"""Session-only evidence upload UI with conservative validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import streamlit as st

from models.schemas import Finding


ALLOWED_MIME_BY_SUFFIX = {
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".txt": {"text/plain", "application/octet-stream"},
    ".json": {"application/json", "text/json", "text/plain"},
    ".pdf": {"application/pdf"},
}


def _validate_file(uploaded, max_upload_mb: int) -> str | None:
    safe_name = Path(uploaded.name).name
    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_MIME_BY_SUFFIX:
        return f"{safe_name}: 지원하지 않는 파일 형식입니다."
    if uploaded.size > max_upload_mb * 1024 * 1024:
        return f"{safe_name}: {max_upload_mb}MB 크기 제한을 초과했습니다."
    if uploaded.type and uploaded.type not in ALLOWED_MIME_BY_SUFFIX[suffix]:
        return f"{safe_name}: 확장자와 MIME 형식이 일치하지 않습니다."
    if suffix == ".json":
        try:
            json.loads(uploaded.getvalue().decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return f"{safe_name}: 올바른 UTF-8 JSON 파일이 아닙니다."
    return None


def render_evidence_upload(findings: list[Finding], max_upload_mb: int) -> None:
    st.session_state.setdefault("session_evidence", [])
    with st.container(border=True):
        st.markdown("**증적자료 업로드**")
        finding_id = st.selectbox(
            "연결할 취약점",
            options=[item.finding_id for item in findings],
            key="evidence_finding_id",
        )
        uploaded_files = st.file_uploader(
            "PNG/JPG, TXT, JSON, PDF",
            type=["png", "jpg", "jpeg", "txt", "json", "pdf"],
            accept_multiple_files=True,
            max_upload_size=max_upload_mb,
            key="evidence_files",
            help="파일은 현재 브라우저 세션 메모리에만 보관되며 실행되지 않습니다.",
        )
        if st.button(
            "세션에 추가",
            type="primary",
            icon=":material/upload:",
            disabled=not uploaded_files,
        ):
            added = 0
            for uploaded in uploaded_files:
                error = _validate_file(uploaded, max_upload_mb)
                if error:
                    st.error(error, icon=":material/error:")
                    continue
                content = uploaded.getvalue()
                digest = hashlib.sha256(
                    Path(uploaded.name).name.encode("utf-8") + content
                ).hexdigest()[:12]
                evidence_id = f"SESSION-{digest.upper()}"
                if any(
                    item["evidence_id"] == evidence_id
                    for item in st.session_state.session_evidence
                ):
                    continue
                st.session_state.session_evidence.append(
                    {
                        "evidence_id": evidence_id,
                        "finding_id": finding_id,
                        "filename": Path(uploaded.name).name,
                        "mime_type": uploaded.type,
                        "size_bytes": uploaded.size,
                        "content": content,
                    }
                )
                added += 1
            if added:
                st.toast(f"증적 {added}개를 현재 세션에 추가했습니다.")
                st.rerun()

        if st.session_state.session_evidence:
            st.caption(f"세션 임시 증적 {len(st.session_state.session_evidence)}개")
            st.dataframe(
                [
                    {
                        "취약점": item["finding_id"],
                        "파일명": item["filename"],
                        "형식": item["mime_type"],
                        "크기": item["size_bytes"],
                    }
                    for item in st.session_state.session_evidence
                ],
                hide_index=True,
                height=180,
                column_config={
                    "크기": st.column_config.NumberColumn(format="%d bytes")
                },
            )
        else:
            st.caption("추가된 세션 증적이 없습니다.")
