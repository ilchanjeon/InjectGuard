import re
import unicodedata


def preprocess(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.strip().lower()
    return re.sub(r"\s+", " ", normalized)
