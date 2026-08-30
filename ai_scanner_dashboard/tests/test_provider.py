from __future__ import annotations

import json
import unittest
from pathlib import Path

from providers.mock_provider import MockDataProvider
from services.normalizer import DataNormalizationError, normalize_scan_output


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "mock_scan_result.json"


class MockProviderTests(unittest.TestCase):
    def test_mock_data_loads_with_required_demo_coverage(self) -> None:
        scan = MockDataProvider(DATA_PATH).get_scan_result()

        self.assertEqual(scan.scan_id, "SCAN-2026-001")
        self.assertEqual(len(scan.findings), 9)
        self.assertEqual(len(scan.evidence), 8)
        self.assertEqual(len(scan.pipeline.steps), 5)

        category_counts = {
            category: sum(item.category == category for item in scan.findings)
            for category in ("SQL Injection", "XSS", "File Upload")
        }
        self.assertEqual(category_counts, {
            "SQL Injection": 3,
            "XSS": 3,
            "File Upload": 3,
        })
        self.assertEqual(
            {item.verification_status for item in scan.findings},
            {"unverified", "verified", "false_positive", "reanalysis_required"},
        )

    def test_invalid_payload_reports_readable_path(self) -> None:
        raw = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        del raw["findings"][0]["finding_id"]

        with self.assertRaisesRegex(DataNormalizationError, "findings\\[0\\].finding_id"):
            normalize_scan_output(raw)


if __name__ == "__main__":
    unittest.main()
