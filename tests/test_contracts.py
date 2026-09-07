import dataclasses

import pytest

from app.contracts import (
    Action,
    DetectionResult,
    DetectorSignal,
    FilterResult,
    ResponseDecision,
    RiskLevel,
)


def test_filter_result_defaults() -> None:
    result = FilterResult(original="A", normalized="a")
    assert result.variants == ()
    assert result.removed_invisible == 0
    assert result.homoglyphs_folded == 0
    assert result.flags == ()


def test_all_texts_includes_normalized_and_variants() -> None:
    result = FilterResult(
        original="A",
        normalized="a",
        variants=("b", "c"),
    )
    assert result.all_texts == ("a", "b", "c")


def test_contracts_are_immutable() -> None:
    signal = DetectorSignal(name="rule", score=1.0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        signal.score = 0.0  # type: ignore[misc]


def test_enums_are_plain_strings() -> None:
    assert RiskLevel.LOW == "low"
    assert Action.BLOCK == "block"


def test_detection_and_decision_construct() -> None:
    signal = DetectorSignal(name="rule", score=1.0, detail="cat:pat")
    detection = DetectionResult(
        signals=(signal,),
        rule_score=1.0,
        embedding_score=0.2,
        evasion_score=0.0,
        matched_pattern="cat:pat",
    )
    decision = ResponseDecision(
        risk_level=RiskLevel.HIGH,
        action=Action.BLOCK,
        risk_score=1.0,
        reason="rule_pattern_detected",
        evidence={"matched_pattern": "cat:pat"},
    )
    assert detection.signals[0].detail == "cat:pat"
    assert decision.action is Action.BLOCK
