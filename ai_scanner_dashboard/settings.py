"""Environment-backed dashboard settings.

No server, API, or model address is hard-coded in the Streamlit UI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    provider: str
    mock_data_path: Path
    tool_api_url: str | None
    tool_result_path: Path | None
    tool_model_name: str | None
    max_upload_mb: int


def load_settings() -> Settings:
    """Load settings without requiring a third-party dotenv package."""
    provider = os.getenv("AI_SCANNER_PROVIDER", "mock").strip().lower()
    mock_path = Path(
        os.getenv(
            "AI_SCANNER_MOCK_DATA_PATH",
            str(BASE_DIR / "data" / "mock_scan_result.json"),
        )
    ).expanduser()

    result_path_raw = os.getenv("AI_SCANNER_RESULT_PATH", "").strip()
    max_upload_mb = int(os.getenv("AI_SCANNER_MAX_UPLOAD_MB", "10"))
    if max_upload_mb < 1:
        raise ValueError("AI_SCANNER_MAX_UPLOAD_MB는 1 이상이어야 합니다.")

    return Settings(
        provider=provider,
        mock_data_path=mock_path,
        tool_api_url=os.getenv("AI_SCANNER_API_URL") or None,
        tool_result_path=Path(result_path_raw).expanduser() if result_path_raw else None,
        tool_model_name=os.getenv("AI_SCANNER_MODEL_NAME") or None,
        max_upload_mb=max_upload_mb,
    )
