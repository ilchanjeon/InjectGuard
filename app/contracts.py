from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Action(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


@dataclass(frozen=True)
class FilterResult:
    """필터모듈의 출력. 원문과 정규화 결과, 그리고 정규화 과정에서 관찰된 신호."""

    original: str
    normalized: str
    variants: tuple[str, ...] = ()
    removed_invisible: int = 0
    homoglyphs_folded: int = 0
    flags: tuple[str, ...] = ()

    @property
    def all_texts(self) -> tuple[str, ...]:
        """탐지기가 검사해야 할 문자열 전체."""
        return (self.normalized, *self.variants)


@dataclass(frozen=True)
class DetectorSignal:
    name: str
    score: float
    detail: str | None = None


@dataclass(frozen=True)
class DetectionResult:
    signals: tuple[DetectorSignal, ...]
    rule_score: float
    embedding_score: float
    evasion_score: float
    matched_pattern: str | None


@dataclass(frozen=True)
class ResponseDecision:
    risk_level: RiskLevel
    action: Action
    risk_score: float
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisResult:
    filter_result: FilterResult
    detection: DetectionResult
    decision: ResponseDecision
    timings: dict[str, float]


@dataclass(frozen=True)
class HandleResult:
    analysis: AnalysisResult
    response_text: str
    llm_called: bool
