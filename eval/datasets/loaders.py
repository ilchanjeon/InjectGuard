from pathlib import Path

from eval.datasets.augment import augment
from eval.datasets.schema import EvalSample, load_jsonl


DATA_DIR = Path(__file__).resolve().parent
KO_EVAL_PATH = DATA_DIR / "ko_eval.jsonl"


class DatasetUnavailable(Exception):
    """공개 데이터셋을 가져올 수 없을 때 발생. 원인을 메시지에 담는다."""


def load_korean() -> list[EvalSample]:
    return load_jsonl(KO_EVAL_PATH)


def load_deepset() -> list[EvalSample]:
    """HuggingFace deepset/prompt-injections 를 공통 스키마로 변환한다."""
    try:
        from datasets import load_dataset
    except ImportError as error:
        raise DatasetUnavailable(
            "datasets 패키지가 필요합니다: pip install datasets"
        ) from error

    try:
        dataset = load_dataset("deepset/prompt-injections")
    except Exception as error:  # 네트워크·인증·스키마 변경 등
        raise DatasetUnavailable(
            f"deepset/prompt-injections 를 불러오지 못했습니다: {error}"
        ) from error

    samples: list[EvalSample] = []
    for split in dataset:
        for row in dataset[split]:
            samples.append(
                EvalSample(
                    text=row["text"],
                    label=int(row["label"]),
                    category=None,
                    lang="en",
                    source="deepset",
                )
            )
    return samples


def load_all(
    include_public: bool = True,
    include_augmented: bool = True,
) -> list[EvalSample]:
    samples = load_korean()

    if include_augmented:
        samples = samples + augment(load_korean())

    if include_public:
        samples = samples + load_deepset()

    return samples
