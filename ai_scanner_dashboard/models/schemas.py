"""Dataclass models shared by mock and future tool providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


Severity = Literal["Critical", "High", "Medium", "Low"]
VerificationStatus = Literal[
    "unverified", "verified", "false_positive", "reanalysis_required"
]
FindingCategory = Literal["SQL Injection", "XSS", "File Upload"]
ProcessStatus = Literal["pending", "running", "completed", "error"]


@dataclass(frozen=True)
class Target:
    name: str
    base_url: str


@dataclass(frozen=True)
class PipelineStep:
    key: Literal["generate", "collect", "connect", "analyze", "visualize"]
    label: str
    status: ProcessStatus
    count: int
    last_processed_at: datetime | None = None
    error: str | None = None


@dataclass(frozen=True)
class Pipeline:
    status: ProcessStatus
    generated_at: datetime | None = None
    collected_at: datetime | None = None
    normalized_at: datetime | None = None
    analyzed_at: datetime | None = None
    steps: list[PipelineStep] = field(default_factory=list)


@dataclass(frozen=True)
class ScanSummary:
    scanned_pages: int
    normal_pages: int = 0


@dataclass(frozen=True)
class Finding:
    finding_id: str
    category: FindingCategory
    url: str
    parameter: str
    initial_severity: Severity
    final_severity: Severity
    verification_status: VerificationStatus
    confidence: float
    evidence_ids: list[str]
    cwe: str | None
    cve: str | None
    cvss: float | None
    summary: str
    detection_basis: str
    http_request_summary: str
    http_response_summary: str
    initial_assessment: str
    analyst_verification: str
    ai_reanalysis: str
    impact: str
    remediation: str
    secure_coding: str
    analyzed_at: datetime


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    type: Literal["screenshot", "log", "http_request", "http_response", "pdf"]
    filename: str
    mime_type: str
    size_bytes: int
    finding_ids: list[str]
    uploaded_at: datetime


@dataclass(frozen=True)
class Report:
    report_id: str
    name: str
    status: ProcessStatus
    updated_at: datetime | None
    summary: str


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    target: Target
    pipeline: Pipeline
    scan_summary: ScanSummary
    findings: list[Finding]
    evidence: list[Evidence]
    reports: list[Report]
    schema_version: str = "1.0"
