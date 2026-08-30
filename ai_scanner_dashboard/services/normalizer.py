"""Normalize provider payloads into the dashboard's stable schema."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping

from models.schemas import (
    Evidence,
    Finding,
    Pipeline,
    PipelineStep,
    Report,
    ScanResult,
    ScanSummary,
    Target,
)


class DataNormalizationError(ValueError):
    """Raised when external or mock data cannot satisfy the shared contract."""


SEVERITIES = {"Critical", "High", "Medium", "Low"}
CATEGORIES = {"SQL Injection", "XSS", "File Upload"}
VERIFICATION_STATUSES = {
    "unverified",
    "verified",
    "false_positive",
    "reanalysis_required",
}
PROCESS_STATUSES = {"pending", "running", "completed", "error"}
STEP_KEYS = {"generate", "collect", "connect", "analyze", "visualize"}
EVIDENCE_TYPES = {"screenshot", "log", "http_request", "http_response", "pdf"}


def _derive_pipeline_steps(payload: dict[str, Any]) -> None:
    pipeline = payload.setdefault("pipeline", {})
    if pipeline.get("steps"):
        return
    findings_count = len(payload.get("findings", []))
    evidence_count = len(payload.get("evidence", []))
    step_data = [
        ("generate", "데이터 생성", findings_count, pipeline.get("generated_at")),
        ("collect", "수집", evidence_count, pipeline.get("collected_at")),
        ("connect", "연결", findings_count, pipeline.get("normalized_at")),
        ("analyze", "분석", findings_count, pipeline.get("analyzed_at")),
        ("visualize", "시각화", findings_count, pipeline.get("analyzed_at")),
    ]
    pipeline["steps"] = [
        {
            "key": key,
            "label": label,
            "status": "completed" if timestamp else "pending",
            "count": count,
            "last_processed_at": timestamp,
            "error": None,
        }
        for key, label, count, timestamp in step_data
    ]


def _apply_common_aliases(payload: dict[str, Any]) -> None:
    if "findings" not in payload and "vulnerabilities" in payload:
        payload["findings"] = payload.pop("vulnerabilities")
    if "target" not in payload and payload.get("target_url"):
        payload["target"] = {
            "name": payload.get("target_name", "Unknown target"),
            "base_url": payload["target_url"],
        }
    for item in payload.setdefault("findings", []):
        if "finding_id" not in item and "id" in item:
            item["finding_id"] = item["id"]
        if "category" not in item and "type" in item:
            item["category"] = item["type"]
        if "initial_severity" not in item and "severity" in item:
            item["initial_severity"] = item["severity"]
        if "final_severity" not in item and item.get("initial_severity"):
            item["final_severity"] = item["initial_severity"]


def _derive_scan_summary(payload: dict[str, Any]) -> None:
    if "scan_summary" not in payload:
        payload["scan_summary"] = {
            "scanned_pages": payload.get(
                "scanned_pages", len(payload.get("findings", []))
            ),
            "normal_pages": payload.get("normal_pages", 0),
        }


def _required(data: Mapping[str, Any], key: str, path: str) -> Any:
    value = data.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise DataNormalizationError(f"{path}.{key}: 필수 값이 없습니다.")
    return value.strip() if isinstance(value, str) else value


def _choice(value: Any, choices: set[str], path: str) -> str:
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise DataNormalizationError(f"{path}: 허용 값은 {allowed}입니다.")
    return str(value)


def _datetime(value: Any, path: str, *, optional: bool = False) -> datetime | None:
    if value in (None, "") and optional:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise DataNormalizationError(f"{path}: ISO 날짜/시간 형식이 아닙니다.") from exc


def _nonnegative_int(value: Any, path: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise DataNormalizationError(f"{path}: 정수여야 합니다.") from exc
    if number < 0:
        raise DataNormalizationError(f"{path}: 0 이상이어야 합니다.")
    return number


def _bounded_float(value: Any, path: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise DataNormalizationError(f"{path}: 숫자여야 합니다.") from exc
    if not minimum <= number <= maximum:
        raise DataNormalizationError(f"{path}: {minimum}~{maximum} 범위여야 합니다.")
    return number


def _parse_pipeline(raw: Mapping[str, Any]) -> Pipeline:
    steps = []
    for index, item in enumerate(raw.get("steps", [])):
        path = f"pipeline.steps[{index}]"
        steps.append(
            PipelineStep(
                key=_choice(_required(item, "key", path), STEP_KEYS, f"{path}.key"),
                label=_required(item, "label", path),
                status=_choice(
                    _required(item, "status", path),
                    PROCESS_STATUSES,
                    f"{path}.status",
                ),
                count=_nonnegative_int(item.get("count", 0), f"{path}.count"),
                last_processed_at=_datetime(
                    item.get("last_processed_at"),
                    f"{path}.last_processed_at",
                    optional=True,
                ),
                error=item.get("error"),
            )
        )
    return Pipeline(
        status=_choice(
            _required(raw, "status", "pipeline"), PROCESS_STATUSES, "pipeline.status"
        ),
        generated_at=_datetime(
            raw.get("generated_at"), "pipeline.generated_at", optional=True
        ),
        collected_at=_datetime(
            raw.get("collected_at"), "pipeline.collected_at", optional=True
        ),
        normalized_at=_datetime(
            raw.get("normalized_at"), "pipeline.normalized_at", optional=True
        ),
        analyzed_at=_datetime(
            raw.get("analyzed_at"), "pipeline.analyzed_at", optional=True
        ),
        steps=steps,
    )


def _parse_finding(item: Mapping[str, Any], index: int) -> Finding:
    path = f"findings[{index}]"
    cvss_raw = item.get("cvss")
    return Finding(
        finding_id=_required(item, "finding_id", path),
        category=_choice(
            _required(item, "category", path), CATEGORIES, f"{path}.category"
        ),
        url=_required(item, "url", path),
        parameter=_required(item, "parameter", path),
        initial_severity=_choice(
            _required(item, "initial_severity", path),
            SEVERITIES,
            f"{path}.initial_severity",
        ),
        final_severity=_choice(
            _required(item, "final_severity", path),
            SEVERITIES,
            f"{path}.final_severity",
        ),
        verification_status=_choice(
            _required(item, "verification_status", path),
            VERIFICATION_STATUSES,
            f"{path}.verification_status",
        ),
        confidence=_bounded_float(item.get("confidence"), f"{path}.confidence", 0, 1),
        evidence_ids=[str(value) for value in item.get("evidence_ids", [])],
        cwe=item.get("cwe"),
        cve=item.get("cve"),
        cvss=(
            _bounded_float(cvss_raw, f"{path}.cvss", 0, 10)
            if cvss_raw is not None
            else None
        ),
        summary=_required(item, "summary", path),
        detection_basis=_required(item, "detection_basis", path),
        http_request_summary=_required(item, "http_request_summary", path),
        http_response_summary=_required(item, "http_response_summary", path),
        initial_assessment=_required(item, "initial_assessment", path),
        analyst_verification=_required(item, "analyst_verification", path),
        ai_reanalysis=_required(item, "ai_reanalysis", path),
        impact=_required(item, "impact", path),
        remediation=_required(item, "remediation", path),
        secure_coding=_required(item, "secure_coding", path),
        analyzed_at=_datetime(
            _required(item, "analyzed_at", path), f"{path}.analyzed_at"
        ),
    )


def _parse_evidence(item: Mapping[str, Any], index: int) -> Evidence:
    path = f"evidence[{index}]"
    return Evidence(
        evidence_id=_required(item, "evidence_id", path),
        type=_choice(
            _required(item, "type", path), EVIDENCE_TYPES, f"{path}.type"
        ),
        filename=_required(item, "filename", path),
        mime_type=_required(item, "mime_type", path),
        size_bytes=_nonnegative_int(item.get("size_bytes"), f"{path}.size_bytes"),
        finding_ids=[str(value) for value in item.get("finding_ids", [])],
        uploaded_at=_datetime(
            _required(item, "uploaded_at", path), f"{path}.uploaded_at"
        ),
    )


def _parse_report(item: Mapping[str, Any], index: int) -> Report:
    path = f"reports[{index}]"
    return Report(
        report_id=_required(item, "report_id", path),
        name=_required(item, "name", path),
        status=_choice(
            _required(item, "status", path), PROCESS_STATUSES, f"{path}.status"
        ),
        updated_at=_datetime(
            item.get("updated_at"), f"{path}.updated_at", optional=True
        ),
        summary=_required(item, "summary", path),
    )


def normalize_scan_output(raw: Mapping[str, Any]) -> ScanResult:
    """Return validated dashboard data without provider-specific fields."""
    if not isinstance(raw, Mapping):
        raise DataNormalizationError("스캔 결과는 JSON 객체 형태여야 합니다.")
    payload = deepcopy(dict(raw))
    payload.setdefault("schema_version", "1.0")
    payload.setdefault("evidence", [])
    payload.setdefault("reports", [])
    _apply_common_aliases(payload)
    _derive_scan_summary(payload)
    _derive_pipeline_steps(payload)

    target_raw = _required(payload, "target", "root")
    summary_raw = _required(payload, "scan_summary", "root")
    pipeline_raw = _required(payload, "pipeline", "root")
    if not all(
        isinstance(value, Mapping)
        for value in (target_raw, summary_raw, pipeline_raw)
    ):
        raise DataNormalizationError(
            "target, pipeline, scan_summary는 JSON 객체여야 합니다."
        )

    return ScanResult(
        schema_version=str(payload["schema_version"]),
        scan_id=_required(payload, "scan_id", "root"),
        target=Target(
            name=_required(target_raw, "name", "target"),
            base_url=_required(target_raw, "base_url", "target"),
        ),
        pipeline=_parse_pipeline(pipeline_raw),
        scan_summary=ScanSummary(
            scanned_pages=_nonnegative_int(
                summary_raw.get("scanned_pages"), "scan_summary.scanned_pages"
            ),
            normal_pages=_nonnegative_int(
                summary_raw.get("normal_pages", 0), "scan_summary.normal_pages"
            ),
        ),
        findings=[
            _parse_finding(item, index)
            for index, item in enumerate(payload.get("findings", []))
        ],
        evidence=[
            _parse_evidence(item, index)
            for index, item in enumerate(payload.get("evidence", []))
        ],
        reports=[
            _parse_report(item, index)
            for index, item in enumerate(payload.get("reports", []))
        ],
    )
