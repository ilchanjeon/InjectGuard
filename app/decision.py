from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True)
class DecisionResult:
    is_attack: bool
    rule_score: float
    embedding_score: float
    matched_pattern: str | None
    reason: str


def make_decision(
    rule_score: float,
    embedding_score: float,
    matched_pattern: str | None,
    embedding_threshold: float | None = None,
) -> DecisionResult:
    threshold = (
        settings.embedding_threshold
        if embedding_threshold is None
        else embedding_threshold
    )

    if rule_score >= 1.0:
        return DecisionResult(
            is_attack=True,
            rule_score=rule_score,
            embedding_score=embedding_score,
            matched_pattern=matched_pattern,
            reason="rule_pattern_detected",
        )

    if embedding_score >= threshold:
        return DecisionResult(
            is_attack=True,
            rule_score=rule_score,
            embedding_score=embedding_score,
            matched_pattern=None,
            reason="embedding_similarity_detected",
        )

    return DecisionResult(
        is_attack=False,
        rule_score=rule_score,
        embedding_score=embedding_score,
        matched_pattern=None,
        reason="safe",
    )
