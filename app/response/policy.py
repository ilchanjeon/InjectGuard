from app.config import settings
from app.contracts import Action, DetectionResult, ResponseDecision, RiskLevel


def decide(
    detection: DetectionResult,
    t_low: float | None = None,
    t_high: float | None = None,
) -> ResponseDecision:
    """탐지 결과를 위험도 3단계 대응으로 변환한다.

    t_low == t_high 이면 MEDIUM 구간이 비어 기존 이진 동작이 그대로 재현된다.
    Phase 0의 기본 설정이 이에 해당한다.
    """
    low = settings.risk_threshold_low if t_low is None else t_low
    high = settings.risk_threshold_high if t_high is None else t_high

    risk_score = max(
        detection.rule_score,
        detection.embedding_score,
        detection.evasion_score,
    )

    if risk_score >= high:
        risk_level, action = RiskLevel.HIGH, Action.BLOCK
    elif risk_score >= low:
        risk_level, action = RiskLevel.MEDIUM, Action.SANITIZE
    else:
        risk_level, action = RiskLevel.LOW, Action.ALLOW

    if action is Action.ALLOW:
        reason = "safe"
        matched_pattern = None
    elif detection.rule_score >= 1.0:
        reason = "rule_pattern_detected"
        matched_pattern = detection.matched_pattern
    else:
        reason = "embedding_similarity_detected"
        matched_pattern = None

    return ResponseDecision(
        risk_level=risk_level,
        action=action,
        risk_score=risk_score,
        reason=reason,
        evidence={
            "matched_pattern": matched_pattern,
            "signals": {s.name: s.score for s in detection.signals},
        },
    )
