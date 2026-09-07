import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from app.config import BASE_DIR, settings
from app.contracts import DetectorSignal, FilterResult


class EmbeddingDetector:
    """공격 예시 문장과의 코사인 유사도 기반 탐지."""

    name = "embedding"

    def __init__(
        self,
        prompt_path: Path | None = None,
        model_name: str | None = None,
    ) -> None:
        self.prompt_path = prompt_path or (
            BASE_DIR / "data" / "attack_prompts.json"
        )
        with self.prompt_path.open(encoding="utf-8") as file:
            self.attack_prompts: list[str] = json.load(file)

        self.model = SentenceTransformer(model_name or settings.embedding_model)
        self.attack_embeddings = self.model.encode(
            self.attack_prompts,
            normalize_embeddings=True,
        )

    def score(self, filter_result: FilterResult) -> DetectorSignal:
        texts = list(filter_result.all_texts)
        embeddings = self.model.encode(texts, normalize_embeddings=True)
        similarities = np.dot(self.attack_embeddings, embeddings.T)
        return DetectorSignal(
            name=self.name,
            score=float(np.max(similarities)),
            detail=None,
        )
