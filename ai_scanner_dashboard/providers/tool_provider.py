"""Future AI Scanner integration boundary.

This module intentionally performs no API calls, file polling, scanning, or AI
inference. Implement only after the real tool contract is delivered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from models.schemas import ScanResult
from providers.base import DataProvider, ProviderError
from services.normalizer import normalize_scan_output


class ToolProviderNotConfigured(ProviderError):
    pass


class ToolDataProvider(DataProvider):
    """Expected adapter for the real AI Scanner.

    Expected input
    --------------
    ``scan_id`` identifying an existing, already-produced tool result.

    Expected output
    ---------------
    A mapping accepted by ``services.normalizer.normalize_scan_output`` and
    ultimately returned as ``models.schemas.ScanResult``.
    """

    def __init__(
        self,
        *,
        api_url: str | None = None,
        result_path: Path | None = None,
        model_name: str | None = None,
    ):
        self.api_url = api_url
        self.result_path = result_path
        self.model_name = model_name

    @property
    def source_label(self) -> str:
        return "AI Scanner 툴"

    def fetch_raw_scan(self, scan_id: str | None = None) -> Mapping[str, Any]:
        """Fetch an existing scan result without initiating a scan.

        Replace this method with the delivered tool's read-only API or result
        file adapter. It must not attack a target or execute uploaded evidence.
        """
        raise ToolProviderNotConfigured(
            "실제 AI Scanner 연결부가 아직 구성되지 않았습니다. "
            "providers/tool_provider.py의 fetch_raw_scan()을 구현해 주세요."
        )

    def get_scan_result(self, scan_id: str | None = None) -> ScanResult:
        """Return normalized data after ``fetch_raw_scan`` is implemented."""
        return normalize_scan_output(self.fetch_raw_scan(scan_id))
