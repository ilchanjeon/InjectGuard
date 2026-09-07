import json

import numpy as np
import pytest

from app.contracts import FilterResult
from app.detection.embedding_detector import EmbeddingDetector


class FakeModel:
    """SentenceTransformer 대역. 실제 모델 로딩(수십 초)을 피한다."""

    def __init__(self, vectors: dict[str, list[float]]) -> None:
        self.vectors = vectors

    def encode(self, texts, normalize_embeddings=False):
        return np.array([self.vectors[t] for t in texts], dtype=np.float32)


@pytest.fixture
def prompt_file(tmp_path):
    path = tmp_path / "attack_prompts.json"
    path.write_text(json.dumps(["공격A", "공격B"]), encoding="utf-8")
    return path


def test_returns_max_similarity(prompt_file, monkeypatch) -> None:
    model = FakeModel(
        {
            "공격A": [1.0, 0.0],
            "공격B": [0.0, 1.0],
            "입력": [0.8, 0.6],
        }
    )
    monkeypatch.setattr(
        "app.detection.embedding_detector.SentenceTransformer",
        lambda name: model,
    )
    detector = EmbeddingDetector(prompt_path=prompt_file)
    signal = detector.score(FilterResult(original="입력", normalized="입력"))

    assert signal.name == "embedding"
    assert signal.score == pytest.approx(0.8, abs=1e-5)
