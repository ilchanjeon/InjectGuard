import pytest

from app.contracts import Action, DetectionResult, DetectorSignal, RiskLevel
from app.response.policy import decide


def make_detection(rule: float = 0.0, embedding: float = 0.0, matched=None):
    return DetectionResult(
        signals=(
            DetectorSignal("rule", rule, matched),
            DetectorSignal("embedding", embedding),
        ),
        rule_score=rule,
        embedding_score=embedding,
        evasion_score=0.0,
        matched_pattern=matched,
    )


def test_rule_detection_blocks_and_takes_priority() -> None:
    decision = decide(make_detection(rule=1.0, embedding=0.1, matched="c:p"), 0.75, 0.75)
    assert decision.action is Action.BLOCK
    assert decision.risk_level is RiskLevel.HIGH
    assert decision.reason == "rule_pattern_detected"
    assert decision.evidence["matched_pattern"] == "c:p"


def test_embedding_above_threshold_blocks() -> None:
    decision = decide(make_detection(embedding=0.8), 0.75, 0.75)
    assert decision.action is Action.BLOCK
    assert decision.reason == "embedding_similarity_detected"
    assert decision.evidence["matched_pattern"] is None


def test_safe_input_is_allowed() -> None:
    decision = decide(make_detection(embedding=0.2), 0.75, 0.75)
    assert decision.action is Action.ALLOW
    assert decision.risk_level is RiskLevel.LOW
    assert decision.reason == "safe"


def test_equal_thresholds_reproduce_binary_behaviour() -> None:
    """t_low == t_high 이면 MEDIUM 구간이 비어 SANITIZE가 나오지 않는다."""
    for score in (0.0, 0.5, 0.74, 0.75, 0.9, 1.0):
        decision = decide(make_detection(embedding=score), 0.75, 0.75)
        assert decision.action in (Action.ALLOW, Action.BLOCK)


def test_split_thresholds_open_sanitize_band() -> None:
    decision = decide(make_detection(embedding=0.6), 0.5, 0.9)
    assert decision.action is Action.SANITIZE
    assert decision.risk_level is RiskLevel.MEDIUM


def test_risk_score_is_max_of_signals() -> None:
    decision = decide(make_detection(rule=0.0, embedding=0.42), 0.75, 0.75)
    assert decision.risk_score == pytest.approx(0.42)
