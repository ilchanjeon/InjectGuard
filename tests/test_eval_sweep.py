import pytest

from eval.datasets.schema import EvalSample
from eval.run_eval import Prediction
from eval.sweep import best_threshold, sweep, write_roc_curve


def make_prediction(label: int, score: float) -> Prediction:
    return Prediction(
        sample=EvalSample(text="x", label=label),
        risk_score=score,
        rule_score=score,
        embedding_score=0.0,
        action="block" if score >= 0.5 else "allow",
        total_ms=1.0,
    )


PREDICTIONS = [
    make_prediction(1, 0.9),
    make_prediction(1, 0.8),
    make_prediction(1, 0.4),
    make_prediction(0, 0.6),
    make_prediction(0, 0.2),
    make_prediction(0, 0.1),
]


def test_sweep_returns_metrics_per_threshold() -> None:
    results = sweep(PREDICTIONS, thresholds=[0.0, 0.5, 1.0])
    assert len(results) == 3
    assert [m.threshold for m in results] == [0.0, 0.5, 1.0]
    # 임계값 0.0 이면 전부 공격 판정 → TPR 1.0, FPR 1.0
    assert results[0].tpr == pytest.approx(1.0)
    assert results[0].fpr == pytest.approx(1.0)


def test_best_threshold_maximises_f1() -> None:
    threshold, metrics = best_threshold(PREDICTIONS, metric="f1")
    assert 0.0 <= threshold <= 1.0
    assert metrics.f1 == max(m.f1 for m in sweep(PREDICTIONS))


def test_best_threshold_rejects_unknown_metric() -> None:
    with pytest.raises(ValueError, match="metric"):
        best_threshold(PREDICTIONS, metric="accuracy")


def test_write_roc_curve_creates_png(tmp_path) -> None:
    path = write_roc_curve(PREDICTIONS, tmp_path / "roc.png")
    assert path.exists()
    assert path.stat().st_size > 0
