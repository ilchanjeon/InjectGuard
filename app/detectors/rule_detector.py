import json
from pathlib import Path

from app.config import BASE_DIR


class RuleDetector:
    def __init__(self, pattern_path: Path | None = None) -> None:
        self.pattern_path = pattern_path or (
            BASE_DIR / "data" / "attack_patterns.json"
        )
        with self.pattern_path.open(encoding="utf-8") as file:
            self.patterns: list[str] = json.load(file)

    def detect(self, text: str) -> tuple[float, str | None]:
        for pattern in self.patterns:
            if pattern.lower() in text:
                return 1.0, pattern
        return 0.0, None
