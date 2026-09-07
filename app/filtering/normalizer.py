import re
import unicodedata

from app.contracts import FilterResult


def normalize(text: str) -> FilterResult:
    """텍스트를 탐지기가 소비할 형태로 정규화한다.

    Phase 0에서는 기존 preprocess()와 동일한 변환만 수행한다.
    불가시 문자 제거·동형이의 폴딩·변형 생성은 Phase 3에서 추가된다.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return FilterResult(original=text, normalized=normalized)
