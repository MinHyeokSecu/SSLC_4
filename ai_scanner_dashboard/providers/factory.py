"""Create providers from environment-backed settings."""

from __future__ import annotations

from providers.base import DataProvider, ProviderError
from providers.mock_provider import MockDataProvider
from providers.tool_provider import ToolDataProvider
from settings import Settings


def create_provider(settings: Settings) -> DataProvider:
    if settings.provider == "mock":
        return MockDataProvider(settings.mock_data_path)
    if settings.provider == "tool":
        return ToolDataProvider(
            api_url=settings.tool_api_url,
            result_path=settings.tool_result_path,
            model_name=settings.tool_model_name,
        )
    raise ProviderError(
        "AI_SCANNER_PROVIDER는 'mock' 또는 'tool'이어야 합니다. "
        f"현재 값: {settings.provider!r}"
    )
