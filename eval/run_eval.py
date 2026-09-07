import argparse
import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.pipeline import Pipeline
from eval.datasets.schema import EvalSample
from eval.metrics import ClassificationMetrics, breakdown, compute, latency_stats


REPORTS_DIR = Path(__file__).resolve().parent / "reports"


@dataclass(frozen=True)
class Prediction:
    sample: EvalSample
    risk_score: float
    rule_score: float
    embedding_score: float
    action: str
    total_ms: float


def run(pipeline: Pipeline, samples: list[EvalSample]) -> list[Prediction]:
    """데이터셋 전체를 analyze()로 통과시킨다. LLM은 호출되지 않는다."""
    predictions: list[Prediction] = []
    for sample in samples:
        analysis = pipeline.analyze(sample.text)
        predictions.append(
            Prediction(
                sample=sample,
                risk_score=analysis.decision.risk_score,
                rule_score=analysis.detection.rule_score,
                embedding_score=analysis.detection.embedding_score,
                action=str(analysis.decision.action),
                total_ms=analysis.timings["total_ms"],
            )
        )
    return predictions


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def _metrics_row(name: str, metrics: ClassificationMetrics) -> dict[str, object]:
    return {
        "group": name,
        "n": metrics.n,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "tn": metrics.tn,
        "fn": metrics.fn,
        "tpr": round(metrics.tpr, 4),
        "fpr": round(metrics.fpr, 4),
        "precision": round(metrics.precision, 4),
        "f1": round(metrics.f1, 4),
        "auroc": None if metrics.auroc is None else round(metrics.auroc, 4),
        "auprc": None if metrics.auprc is None else round(metrics.auprc, 4),
    }


def write_report(
    predictions: list[Prediction],
    reports_dir: Path,
    threshold: float,
    config_version: str,
) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = reports_dir / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    y_true = [p.sample.label for p in predictions]
    y_score = [p.risk_score for p in predictions]

    with (out_dir / "predictions.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "text", "label", "category", "lang", "source", "variant",
                "risk_score", "rule_score", "embedding_score", "action", "total_ms",
            ]
        )
        for p in predictions:
            writer.writerow(
                [
                    p.sample.text, p.sample.label, p.sample.category, p.sample.lang,
                    p.sample.source, p.sample.variant, p.risk_score, p.rule_score,
                    p.embedding_score, p.action, round(p.total_ms, 3),
                ]
            )

    rows = [_metrics_row("overall", compute(y_true, y_score, threshold))]
    for group_name, keys in (
        ("lang", [p.sample.lang for p in predictions]),
        ("source", [p.sample.source for p in predictions]),
        ("variant", [p.sample.variant or "none" for p in predictions]),
        ("category", [p.sample.category or "benign" for p in predictions]),
    ):
        for key, metrics in breakdown(y_true, y_score, keys, threshold).items():
            rows.append(_metrics_row(f"{group_name}={key}", metrics))

    with (out_dir / "metrics.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    latency = latency_stats([p.total_ms for p in predictions])
    overall = compute(y_true, y_score, threshold)

    summary = [
        "# 평가 결과",
        "",
        f"- 실행 시각: {stamp}",
        f"- git commit: {_git_commit()}",
        f"- config_version: {config_version}",
        f"- 임계값: {threshold}",
        f"- 표본 수: {overall.n} (공격 {sum(y_true)}, 정상 {overall.n - sum(y_true)})",
        "",
        "## 전체 지표",
        "",
        f"- TPR(탐지율): {overall.tpr:.4f}",
        f"- FPR(오탐율): {overall.fpr:.4f}",
        f"- Precision: {overall.precision:.4f}",
        f"- F1: {overall.f1:.4f}",
        f"- AUROC: {overall.auroc if overall.auroc is None else f'{overall.auroc:.4f}'}",
        f"- AUPRC: {overall.auprc if overall.auprc is None else f'{overall.auprc:.4f}'}",
        "",
        "## 지연시간 (ms)",
        "",
        f"- p50: {latency['p50']:.3f} / p95: {latency['p95']:.3f} / p99: {latency['p99']:.3f}",
        "",
        "분해 지표는 `metrics.csv`, 개별 예측은 `predictions.csv` 참조.",
        "",
    ]

    from eval.sweep import best_threshold, write_roc_curve

    try:
        write_roc_curve(predictions, out_dir / "roc.png")
        tuned_threshold, tuned = best_threshold(predictions, metric="f1")
    except ValueError:
        # 한쪽 클래스만 있으면 ROC를 그릴 수 없다
        tuned_threshold, tuned = threshold, overall

    summary.extend(
        [
            "## 임계값 스윕",
            "",
            f"- F1 최대 임계값: {tuned_threshold:.2f}",
            f"- 그때의 TPR: {tuned.tpr:.4f}, FPR: {tuned.fpr:.4f}, F1: {tuned.f1:.4f}",
            f"- 현재 설정({threshold}) 대비 F1 변화: {tuned.f1 - overall.f1:+.4f}",
            "",
        ]
    )

    (out_dir / "summary.md").write_text("\n".join(summary), encoding="utf-8")

    (out_dir / "config.json").write_text(
        json.dumps(
            {
                "threshold": threshold,
                "config_version": config_version,
                "git_commit": _git_commit(),
                "timestamp": stamp,
                "latency_ms": latency,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return out_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InjectGuard 평가 하니스")
    parser.add_argument("--no-public", action="store_true", help="공개 데이터셋 제외")
    parser.add_argument("--no-augmented", action="store_true", help="회피 증강본 제외")
    args = parser.parse_args(argv)

    from app.config import settings
    from app.detection.embedding_detector import EmbeddingDetector
    from app.detection.rule_detector import RuleDetector
    from eval.datasets.loaders import DatasetUnavailable, load_all

    try:
        samples = load_all(
            include_public=not args.no_public,
            include_augmented=not args.no_augmented,
        )
    except DatasetUnavailable as error:
        print(f"[경고] {error}")
        print("[경고] 공개 데이터셋 없이 진행합니다.")
        samples = load_all(include_public=False, include_augmented=not args.no_augmented)

    print(f"표본 {len(samples)}건 로드. 임베딩 모델을 준비합니다...")
    pipeline = Pipeline(
        rule_detector=RuleDetector(),
        embedding_detector=EmbeddingDetector(),
    )

    print("평가 실행 중...")
    predictions = run(pipeline, samples)
    out_dir = write_report(
        predictions,
        REPORTS_DIR,
        threshold=settings.risk_threshold_low,
        config_version=settings.config_version,
    )
    print(f"완료: {out_dir}")
    print((out_dir / "summary.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
