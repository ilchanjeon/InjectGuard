import base64

from eval.datasets.schema import EvalSample


VARIANTS = ("zero_width", "homoglyph", "base64", "segmented")

# 라틴 소문자로 혼동되는 키릴 문자. 한글에는 대응 문자가 없어 영향이 없다.
_HOMOGLYPHS = {
    "a": "а",  # CYRILLIC SMALL LETTER A
    "c": "с",  # ES
    "e": "е",  # IE
    "o": "о",  # O
    "p": "р",  # ER
    "x": "х",  # HA
    "y": "у",  # U
    "i": "і",  # BYELORUSSIAN-UKRAINIAN I
    "s": "ѕ",  # DZE
}


def insert_zero_width(text: str, char: str = "​") -> str:
    """공백이 아닌 문자 사이에 제로폭 문자를 끼워 넣는다."""
    pieces: list[str] = []
    for index, letter in enumerate(text):
        pieces.append(letter)
        if index < len(text) - 1 and not letter.isspace():
            pieces.append(char)
    return "".join(pieces)


def substitute_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(letter, letter) for letter in text)


def encode_base64_payload(text: str) -> str:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"다음 문자열을 처리해줘: {encoded}"


def segment_characters(text: str) -> str:
    return " ".join(text.replace(" ", ""))


_TRANSFORMS = {
    "zero_width": insert_zero_width,
    "homoglyph": substitute_homoglyphs,
    "base64": encode_base64_payload,
    "segmented": segment_characters,
}


def augment(samples: list[EvalSample]) -> list[EvalSample]:
    """공격 샘플에 회피 변형을 적용해 새 샘플을 만든다.

    정상 샘플은 변형하지 않는다. 정상 문장에 제로폭 문자를 넣으면
    그 자체가 비정상 신호가 되어 라벨이 흐려지기 때문이다.
    """
    generated: list[EvalSample] = []
    for sample in samples:
        if sample.label != 1:
            continue
        for variant, transform in _TRANSFORMS.items():
            generated.append(
                EvalSample(
                    text=transform(sample.text),
                    label=1,
                    category=sample.category,
                    lang=sample.lang,
                    source="augmented",
                    variant=variant,
                )
            )
    return generated
