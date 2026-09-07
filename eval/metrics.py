from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


@dataclass(frozen=True)
class ClassificationMetrics:
    threshold: float
    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    tpr: float
    fpr: float
    precision: float
    f1: float
    auroc: float | None
    auprc: float | None


def _safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute(
    y_true: Sequence[int],
    y_score: Sequence[float],
    threshold: float,
) -> ClassificationMetrics:
    """이진 분류 지표를 계산한다.

    점수가 임계값 이상이면 공격으로 판정한다. app.response.policy.decide 가
    `>=` 를 쓰므로 동일한 규칙을 적용해야 하니스와 런타임이 일치한다.
    """
    truth = np.asarray(y_true, dtype=int)
    scores = np.asarray(y_score, dtype=float)
    predicted = (scores >= threshold).astype(int)

    tp = int(np.sum((truth == 1) & (predicted == 1)))
    fp = int(np.sum((truth == 0) & (predicted == 1)))
    tn = int(np.sum((truth == 0) & (predicted == 0)))
    fn = int(np.sum((truth == 1) & (predicted == 0)))

    tpr = _safe_divide(tp, tp + fn)
    fpr = _safe_divide(fp, fp + tn)
    precision = _safe_divide(tp, tp + fp)
    f1 = _safe_divide(2 * precision * tpr, precision + tpr)

    # 한쪽 클래스만 존재하면 순위 기반 지표가 정의되지 않는다.
    if len(np.unique(truth)) < 2:
        auroc = None
        auprc = None
    else:
        auroc = float(roc_auc_score(truth, scores))
        auprc = float(average_precision_score(truth, scores))

    return ClassificationMetrics(
        threshold=threshold,
        n=len(truth),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        tpr=tpr,
        fpr=fpr,
        precision=precision,
        f1=f1,
        auroc=auroc,
        auprc=auprc,
    )


def breakdown(
    y_true: Sequence[int],
    y_score: Sequence[float],
    keys: Sequence[str],
    threshold: float,
) -> dict[str, ClassificationMetrics]:
    """언어별·카테고리별·회피유형별 분해 리포트."""
    grouped: dict[str, tuple[list[int], list[float]]] = defaultdict(
        lambda: ([], [])
    )
    for truth, score, key in zip(y_true, y_score, keys, strict=True):
        grouped[key][0].append(truth)
        grouped[key][1].append(score)

    return {
        key: compute(truths, scores, threshold)
        for key, (truths, scores) in grouped.items()
    }


def latency_stats(values: Sequence[float]) -> dict[str, float]:
    array = np.asarray(values, dtype=float)
    if array.size == 0:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "max": 0.0}
    return {
        "p50": float(np.percentile(array, 50)),
        "p95": float(np.percentile(array, 95)),
        "p99": float(np.percentile(array, 99)),
        "mean": float(np.mean(array)),
        "max": float(np.max(array)),
    }
