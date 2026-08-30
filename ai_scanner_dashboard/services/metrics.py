"""Pure metric and table transformations for the dashboard."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from models.schemas import Finding, ScanResult


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
CATEGORY_ORDER = ["SQL Injection", "XSS", "File Upload"]
STATUS_LABELS = {
    "unverified": "미검증",
    "verified": "검증 완료",
    "false_positive": "오탐/제외",
    "reanalysis_required": "재분석 필요",
}
PROCESS_LABELS = {
    "pending": "대기",
    "running": "진행 중",
    "completed": "완료",
    "error": "오류",
}


@dataclass(frozen=True)
class DashboardMetrics:
    scanned_pages: int
    total_findings: int
    verified_findings: int
    false_positives: int
    critical_high: int
    evidence_count: int
    final_report_status: str


def compute_dashboard_metrics(
    scan: ScanResult, session_evidence_count: int = 0
) -> DashboardMetrics:
    final_report = next(
        (report for report in scan.reports if report.report_id == "final-report"), None
    )
    return DashboardMetrics(
        scanned_pages=scan.scan_summary.scanned_pages,
        total_findings=len(scan.findings),
        verified_findings=sum(
            finding.verification_status == "verified" for finding in scan.findings
        ),
        false_positives=sum(
            finding.verification_status == "false_positive"
            for finding in scan.findings
        ),
        critical_high=sum(
            finding.final_severity in {"Critical", "High"}
            for finding in scan.findings
        ),
        evidence_count=len(scan.evidence) + session_evidence_count,
        final_report_status=(
            PROCESS_LABELS[final_report.status] if final_report else "대기"
        ),
    )


def findings_frame(findings: list[Finding]) -> pd.DataFrame:
    rows = [
        {
            "취약점 ID": item.finding_id,
            "대상 URL": item.url,
            "취약점 유형": item.category,
            "탐지 위치": item.parameter,
            "1차 위험도": item.initial_severity,
            "최종 위험도": item.final_severity,
            "검증 상태": STATUS_LABELS[item.verification_status],
            "증적": "있음" if item.evidence_ids else "없음",
            "신뢰도": item.confidence,
            "마지막 분석": item.analyzed_at,
        }
        for item in findings
    ]
    return pd.DataFrame(rows)


def category_counts(findings: list[Finding]) -> pd.DataFrame:
    counts = pd.Series([item.category for item in findings]).value_counts()
    return pd.DataFrame(
        {
            "취약점 유형": CATEGORY_ORDER,
            "탐지 건수": [int(counts.get(name, 0)) for name in CATEGORY_ORDER],
        }
    )


def severity_counts(findings: list[Finding]) -> pd.DataFrame:
    counts = pd.Series([item.final_severity for item in findings]).value_counts()
    return pd.DataFrame(
        {
            "위험도": SEVERITY_ORDER,
            "탐지 건수": [int(counts.get(name, 0)) for name in SEVERITY_ORDER],
        }
    )


def verification_counts(findings: list[Finding]) -> pd.DataFrame:
    raw_order = ["unverified", "verified", "false_positive", "reanalysis_required"]
    counts = pd.Series([item.verification_status for item in findings]).value_counts()
    return pd.DataFrame(
        {
            "검증 상태": [STATUS_LABELS[key] for key in raw_order],
            "탐지 건수": [int(counts.get(key, 0)) for key in raw_order],
        }
    )


def severity_comparison(findings: list[Finding]) -> pd.DataFrame:
    rows = []
    for severity in SEVERITY_ORDER:
        rows.extend(
            [
                {
                    "위험도": severity,
                    "판정 시점": "1차 스캔",
                    "탐지 건수": sum(
                        item.initial_severity == severity for item in findings
                    ),
                },
                {
                    "위험도": severity,
                    "판정 시점": "증적 반영 후",
                    "탐지 건수": sum(
                        item.final_severity == severity for item in findings
                    ),
                },
            ]
        )
    return pd.DataFrame(rows)
