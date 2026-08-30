from __future__ import annotations

import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

from components.evidence import _validate_file


ROOT = Path(__file__).resolve().parents[1]


class FakeUpload:
    def __init__(self, name: str, mime_type: str, content: bytes):
        self.name = name
        self.type = mime_type
        self.size = len(content)
        self._content = content

    def getvalue(self) -> bytes:
        return self._content


class StreamlitSmokeTests(unittest.TestCase):
    def test_app_renders_core_dashboard_without_exception(self) -> None:
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()

        self.assertEqual(list(app.exception), [])
        self.assertEqual(app.title[0].value, "AI Scanner 보안 진단")
        self.assertGreaterEqual(len(app.metric), 12)
        self.assertGreaterEqual(len(app.dataframe), 1)
        self.assertEqual(app.subheader[0].value, "진단 흐름")
        self.assertEqual(len(app.get("file_uploader")), 1)

    def test_category_filter_updates_findings_table(self) -> None:
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
        app.multiselect[0].set_value(["XSS"]).run()

        self.assertEqual(list(app.exception), [])
        table = app.dataframe[0].value
        self.assertEqual(len(table), 3)
        self.assertEqual(table["취약점 유형"].unique().tolist(), ["XSS"])

    def test_evidence_validation_accepts_json_and_rejects_disguised_file(self) -> None:
        valid = FakeUpload("response.json", "application/json", b'{"status": 200}')
        disguised = FakeUpload("capture.png", "application/pdf", b"not-an-image")

        self.assertIsNone(_validate_file(valid, 10))
        self.assertIn("MIME", _validate_file(disguised, 10))


if __name__ == "__main__":
    unittest.main()
