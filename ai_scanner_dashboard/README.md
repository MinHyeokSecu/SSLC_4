# AI Scanner dashboard

생성형 AI 기반 웹 취약점 진단 결과를 보안담당자가 검토하고, 증적을 연결해 재분석 및 보고서 상태를 확인하기 위한 Streamlit 대시보드입니다. 현재 버전은 실제 서버나 AI 툴을 호출하지 않고 JSON 모의 데이터만 사용합니다.

## 핵심 흐름

화면 상단에서 다음 처리 상태가 한 방향으로 이어집니다.

`데이터 생성 → 수집 → 연결 → 분석 → 시각화`

각 단계는 상태, 처리 건수, 마지막 처리 시각, 오류 여부를 표시합니다. 그 아래에는 핵심 지표, 취약점 유형·위험도·검증 상태 차트, 1차/최종 판정 비교, 필터 가능한 취약점 표와 상세 정보가 배치됩니다.

## 폴더 구조

```text
ai_scanner_dashboard/
├── app.py
├── settings.py
├── components/             # Streamlit 화면 구성 요소
├── providers/              # 모의/실제 툴 데이터 공급 계약
├── services/               # 정규화와 지표 계산
├── models/                 # dataclass 데이터 모델
├── data/
│   └── mock_scan_result.json
├── tests/
├── .streamlit/
│   └── config.toml
├── .env.example
├── requirements.txt
└── README.md
```

## 설치 및 PowerShell 실행

```powershell
cd C:\redred\ai_scanner_dashboard
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

현재 PC에 의존성이 이미 설치되어 있다면 가상환경 생성 없이 아래 명령만 실행할 수 있습니다.

```powershell
cd C:\redred\ai_scanner_dashboard
python -m streamlit run app.py
```

## 모의 데이터

`data/mock_scan_result.json`은 다음 내용을 포함합니다.

- 스캔 ID, 대상 시스템, 5단계 파이프라인 상태
- SQL Injection, XSS, File Upload 각 3건
- 미검증, 검증 완료, 오탐/제외, 재분석 필요 상태
- HTTP 요약, 캡처, 로그, PDF 등 증적 메타데이터
- 1차 보고서, 증적 재분석, 최종 보고서, 시큐어코딩 가이드 상태

UI는 이 JSON 파일을 직접 읽지 않습니다. `MockDataProvider`가 읽은 원본을 `services/normalizer.py`에서 공통 `ScanResult`로 변환한 뒤 UI에 전달합니다.

## 실제 AI Scanner 연결

실제 툴을 전달받으면 다음 두 곳만 중심으로 수정합니다.

1. `providers/tool_provider.py`의 `fetch_raw_scan()`에서 이미 생성된 스캔 결과를 읽습니다.
2. 툴 출력 필드명이 공통 스키마와 다르면 `services/normalizer.py`에 매핑 규칙을 추가합니다.

`fetch_raw_scan()`의 입력은 선택적 `scan_id`, 출력은 JSON 호환 `Mapping`입니다. 이 메서드는 스캔을 시작하거나 공격을 수행하지 않고 기존 결과만 읽어야 합니다.

환경변수로 Provider를 전환합니다.

```powershell
$env:AI_SCANNER_PROVIDER = "tool"
$env:AI_SCANNER_API_URL = "https://tool-api.example"
# 또는
$env:AI_SCANNER_RESULT_PATH = "C:\path\to\existing\result.json"
python -m streamlit run app.py
```

실제 출력 계약이 확정되기 전이므로 API 주소, 결과 경로, 모델명은 UI에 하드코딩하지 않았습니다. `.env.example`은 설정 항목 예시이며, 비밀값을 저장하지 않습니다.

## 증적 업로드 안전 범위

- 허용 형식: PNG/JPG, TXT, JSON, PDF
- 기본 최대 크기: 파일당 10MB
- 확장자, MIME, 크기와 JSON 문법을 검사
- 업로드 바이트는 현재 Streamlit 세션 메모리에만 임시 보관
- 파일 실행, 서버 전송, 기존 포털 저장소 기록을 수행하지 않음

## 테스트

```powershell
cd C:\redred\ai_scanner_dashboard
python -m unittest discover -s tests -v
```

테스트는 모의 데이터 스키마, 유형/상태 포함 여부, KPI·차트 합계, Streamlit 기본 렌더링을 확인합니다.

## 기존 서버와의 분리

대시보드는 `ai_scanner_dashboard` 폴더 안에서 독립 실행됩니다. 상위 디렉터리의 PHP, HTML, CSS, JavaScript, SQL, DB 설정을 import하거나 수정하지 않으며, 취약 웹 서버나 데이터베이스를 실행·중지·스캔하지 않습니다.
