from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # 헤드리스 환경에서 GUI 백엔드를 쓰지 않는다

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

from eval.metrics import ClassificationMetrics, compute  # noqa: E402


DEFAULT_THRESHOLDS = [round(float(x), 2) for x in np.arange(0.0, 1.01, 0.01)]

_METRIC_FIELDS = {"f1", "tpr", "precision"}


def sweep(predictions, thresholds=None) -> list[ClassificationMetrics]:
    y_true = [p.sample.label for p in predictions]
    y_score = [p.risk_score for p in predictions]
    grid = DEFAULT_THRESHOLDS if thresholds is None else thresholds
    return [compute(y_true, y_score, threshold) for threshold in grid]


def best_threshold(predictions, metric: str = "f1"):
    if metric not in _METRIC_FIELDS:
        raise ValueError(
            f"지원하지 않는 metric입니다: {metric} (가능: {sorted(_METRIC_FIELDS)})"
        )
    results = sweep(predictions)
    best = max(results, key=lambda m: getattr(m, metric))
    return best.threshold, best


def write_roc_curve(predictions, out_path: Path) -> Path:
    y_true = [p.sample.label for p in predictions]
    y_score = [p.risk_score for p in predictions]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fpr, tpr, _ = roc_curve(y_true, y_score)

    figure, axes = plt.subplots(figsize=(5, 5))
    axes.plot(fpr, tpr, label="InjectGuard")
    axes.plot([0, 1], [0, 1], linestyle="--", linewidth=1, label="random")
    axes.set_xlabel("False Positive Rate")
    axes.set_ylabel("True Positive Rate")
    axes.set_title("ROC Curve")
    axes.legend()
    figure.tight_layout()
    figure.savefig(out_path, dpi=150)
    plt.close(figure)

    return out_path
