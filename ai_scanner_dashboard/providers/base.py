"""Stable provider contract consumed by the Streamlit UI."""

from __future__ import annotations

from abc import ABC, abstractmethod

from models.schemas import ScanResult


class ProviderError(RuntimeError):
    """Readable provider failure that the UI can display without crashing."""


class DataProvider(ABC):
    @property
    @abstractmethod
    def source_label(self) -> str:
        """Short label displayed as the current data source."""

    @abstractmethod
    def get_scan_result(self, scan_id: str | None = None) -> ScanResult:
        """Return one normalized scan result for the dashboard."""
