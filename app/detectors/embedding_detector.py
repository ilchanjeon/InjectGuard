import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from app.config import BASE_DIR, settings


class EmbeddingDetector:
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

        self.model = SentenceTransformer(
            model_name or settings.embedding_model
        )
        self.attack_embeddings = self.model.encode(
            self.attack_prompts,
            normalize_embeddings=True,
        )

    def detect(self, text: str) -> float:
        input_embedding = self.model.encode(
            [text],
            normalize_embeddings=True,
        )[0]
        similarities = np.dot(self.attack_embeddings, input_embedding)
        return float(np.max(similarities))
