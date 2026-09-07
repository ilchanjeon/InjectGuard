import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _threshold(name: str) -> float:
    """RISK_THRESHOLD_* 를 읽되, 없으면 구 EMBEDDING_THRESHOLD 로 폴백한다."""
    fallback = os.getenv("EMBEDDING_THRESHOLD", "0.75")
    return float(os.getenv(name, fallback))


def _file_digest(path: Path) -> str:
    if not path.exists():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


@dataclass(frozen=True)
class Settings:
    app_name: str = "InjectGuard"
    embedding_model: str = os.getenv(
        "EMBEDDING_MODEL",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    )
    embedding_threshold: float = float(os.getenv("EMBEDDING_THRESHOLD", "0.75"))
    risk_threshold_low: float = _threshold("RISK_THRESHOLD_LOW")
    risk_threshold_high: float = _threshold("RISK_THRESHOLD_HIGH")
    audit_log_message: bool = os.getenv("AUDIT_LOG_MESSAGE", "true").lower() == "true"
    enable_raw_endpoint: bool = (
        os.getenv("ENABLE_RAW_ENDPOINT", "false").lower() == "true"
    )
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_api_base: str = os.getenv(
        "GEMINI_API_BASE",
        "https://generativelanguage.googleapis.com/v1beta",
    )
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    gemini_timeout_seconds: float = float(
        os.getenv("GEMINI_TIMEOUT_SECONDS", "60")
    )

    @property
    def gemini_generate_url(self) -> str:
        return f"{self.gemini_api_base}/models/{self.gemini_model}:generateContent"

    @property
    def config_version(self) -> str:
        """실험 조건 식별자. 감사 로그와 평가 리포트에 기록해 재현성을 확보한다."""
        payload = "|".join(
            [
                self.embedding_model,
                f"{self.risk_threshold_low}",
                f"{self.risk_threshold_high}",
                _file_digest(BASE_DIR / "data" / "attack_patterns.json"),
                _file_digest(BASE_DIR / "data" / "attack_prompts.json"),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


settings = Settings()
