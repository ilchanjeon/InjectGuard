from app.decision import make_decision


def test_rule_detection_has_priority() -> None:
    result = make_decision(1.0, 0.1, "ignore previous instructions")
    assert result.is_attack is True
    assert result.reason == "rule_pattern_detected"


def test_embedding_threshold_blocks_attack() -> None:
    result = make_decision(0.0, 0.8, None, embedding_threshold=0.75)
    assert result.is_attack is True
    assert result.reason == "embedding_similarity_detected"


def test_safe_input_is_allowed() -> None:
    result = make_decision(0.0, 0.2, None, embedding_threshold=0.75)
    assert result.is_attack is False
    assert result.reason == "safe"
