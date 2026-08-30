from __future__ import annotations

import unittest
from pathlib import Path

from providers.mock_provider import MockDataProvider
from services.metrics import (
    category_counts,
    compute_dashboard_metrics,
    severity_comparison,
    severity_counts,
    verification_counts,
)


ROOT = Path(__file__).resolve().parents[1]
SCAN = MockDataProvider(ROOT / "data" / "mock_scan_result.json").get_scan_result()


class MetricTests(unittest.TestCase):
    def test_kpis_match_source_data(self) -> None:
        metrics = compute_dashboard_metrics(SCAN)

        self.assertEqual(metrics.scanned_pages, 24)
        self.assertEqual(metrics.total_findings, 9)
        self.assertEqual(metrics.verified_findings, 3)
        self.assertEqual(metrics.false_positives, 2)
        self.assertEqual(metrics.critical_high, 5)
        self.assertEqual(metrics.evidence_count, 8)
        self.assertEqual(metrics.final_report_status, "진행 중")

    def test_chart_totals_equal_findings(self) -> None:
        self.assertEqual(category_counts(SCAN.findings)["탐지 건수"].sum(), 9)
        self.assertEqual(severity_counts(SCAN.findings)["탐지 건수"].sum(), 9)
        self.assertEqual(verification_counts(SCAN.findings)["탐지 건수"].sum(), 9)

        comparison = severity_comparison(SCAN.findings)
        totals = comparison.groupby("판정 시점")["탐지 건수"].sum().to_dict()
        self.assertEqual(totals, {"1차 스캔": 9, "증적 반영 후": 9})


if __name__ == "__main__":
    unittest.main()
