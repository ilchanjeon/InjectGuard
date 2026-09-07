import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class EvalSample:
    """평가 데이터 한 건. 출처가 달라도 이 형태로 통일한다."""

    text: str
    label: int              # 1 = 공격, 0 = 정상
    category: str | None = None
    lang: str = "ko"
    source: str = "handcrafted"
    variant: str | None = None   # 회피 유형 (augment.py가 채움)

    def __post_init__(self) -> None:
        if self.label not in (0, 1):
            raise ValueError(f"label은 0 또는 1이어야 합니다: {self.label}")


def save_jsonl(samples: Iterable[EvalSample], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for sample in samples:
            file.write(json.dumps(asdict(sample), ensure_ascii=False) + "\n")


def load_jsonl(path: Path) -> list[EvalSample]:
    samples: list[EvalSample] = []
    with path.open(encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            samples.append(EvalSample(**json.loads(line)))
    return samples
