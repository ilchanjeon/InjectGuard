import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


@dataclass(frozen=True)
class Settings:
    app_name: str = "InjectGuard"
    embedding_model: str = os.getenv(
        "EMBEDDING_MODEL",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    )
    embedding_threshold: float = float(os.getenv("EMBEDDING_THRESHOLD", "0.75"))
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


settings = Settings()
