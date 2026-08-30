"""JSON-backed provider used until the AI Scanner tool is delivered."""

from __future__ import annotations

import json
from pathlib import Path

from models.schemas import ScanResult
from providers.base import DataProvider, ProviderError
from services.normalizer import DataNormalizationError, normalize_scan_output


class MockDataProvider(DataProvider):
    def __init__(self, json_path: Path):
        self.json_path = json_path

    @property
    def source_label(self) -> str:
        return "JSON 모의 데이터"

    def get_scan_result(self, scan_id: str | None = None) -> ScanResult:
        try:
            raw = json.loads(self.json_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProviderError(f"모의 데이터 파일이 없습니다: {self.json_path}") from exc
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"모의 데이터 JSON 형식 오류: {exc.msg} (줄 {exc.lineno})"
            ) from exc
        except OSError as exc:
            raise ProviderError(f"모의 데이터 파일을 읽을 수 없습니다: {exc}") from exc

        try:
            result = normalize_scan_output(raw)
        except DataNormalizationError as exc:
            raise ProviderError(str(exc)) from exc

        if scan_id and result.scan_id != scan_id:
            raise ProviderError(f"스캔 ID를 찾을 수 없습니다: {scan_id}")
        return result
