import pytest

from eval.metrics import breakdown, compute, latency_stats


def test_known_confusion_matrix() -> None:
    """손으로 계산한 값과 대조한다.

    임계값 0.5 기준:
      y_true = [1, 1, 1, 1, 0, 0, 0, 0]
      y_pred = [1, 1, 1, 0, 1, 0, 0, 0]
    TP=3, FN=1, FP=1, TN=3
    TPR = 3/4 = 0.75,  FPR = 1/4 = 0.25
    Precision = 3/4 = 0.75,  F1 = 2*0.75*0.75/(0.75+0.75) = 0.75
    """
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    y_score = [0.9, 0.8, 0.6, 0.4, 0.7, 0.3, 0.2, 0.1]

    m = compute(y_true, y_score, threshold=0.5)

    assert (m.tp, m.fn, m.fp, m.tn) == (3, 1, 1, 3)
    assert m.tpr == pytest.approx(0.75)
    assert m.fpr == pytest.approx(0.25)
    assert m.precision == pytest.approx(0.75)
    assert m.f1 == pytest.approx(0.75)
    assert m.n == 8


def test_perfect_separation_gives_auroc_one() -> None:
    m = compute([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9], threshold=0.5)
    assert m.auroc == pytest.approx(1.0)
    assert m.tpr == pytest.approx(1.0)
    assert m.fpr == pytest.approx(0.0)


def test_single_class_yields_none_auroc() -> None:
    """한쪽 클래스만 있으면 AUROC가 정의되지 않는다. 예외 대신 None."""
    m = compute([1, 1, 1], [0.9, 0.8, 0.7], threshold=0.5)
    assert m.auroc is None
    assert m.tpr == pytest.approx(1.0)


def test_threshold_is_inclusive() -> None:
    """점수가 임계값과 같으면 공격으로 판정한다 (policy.decide와 동일 규칙)."""
    m = compute([1], [0.75], threshold=0.75)
    assert m.tp == 1


def test_breakdown_splits_by_key() -> None:
    result = breakdown(
        y_true=[1, 0, 1, 0],
        y_score=[0.9, 0.1, 0.2, 0.8],
        keys=["ko", "ko", "en", "en"],
        threshold=0.5,
    )
    assert set(result) == {"ko", "en"}
    assert result["ko"].tp == 1
    assert result["ko"].fp == 0
    assert result["en"].tp == 0
    assert result["en"].fp == 1


def test_latency_stats() -> None:
    stats = latency_stats([1.0, 2.0, 3.0, 4.0, 100.0])
    assert stats["p50"] == pytest.approx(3.0)
    assert stats["mean"] == pytest.approx(22.0)
    assert stats["max"] == pytest.approx(100.0)
