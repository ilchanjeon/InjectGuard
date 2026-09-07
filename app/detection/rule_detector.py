import json
import re
from pathlib import Path

from app.config import BASE_DIR
from app.contracts import DetectorSignal, FilterResult


class RuleDetector:
    """정규식 패턴 기반 탐지.

    Phase 0에서는 기존 동작을 그대로 유지한다: 첫 매치에서 1.0을 반환하는
    이진 점수. 연속 점수화(noisy-OR + 카테고리 가중치)는 Phase 3에서 도입한다.
    """

    name = "rule"

    def __init__(self, pattern_path: Path | None = None) -> None:
        self.pattern_path = pattern_path or (
            BASE_DIR / "data" / "attack_patterns.json"
        )
        with self.pattern_path.open(encoding="utf-8") as file:
            self.patterns_by_category: dict[str, list[str]] = json.load(file)

    def score(self, filter_result: FilterResult) -> DetectorSignal:
        for text in filter_result.all_texts:
            for category, patterns in self.patterns_by_category.items():
                for pattern in patterns:
                    if re.search(pattern, text, flags=re.IGNORECASE):
                        return DetectorSignal(
                            name=self.name,
                            score=1.0,
                            detail=f"{category}:{pattern}",
                        )
        return DetectorSignal(name=self.name, score=0.0, detail=None)
