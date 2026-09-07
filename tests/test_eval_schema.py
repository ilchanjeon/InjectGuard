import pytest

from eval.datasets.schema import EvalSample, load_jsonl, save_jsonl


def test_roundtrip(tmp_path) -> None:
    samples = [
        EvalSample(text="공격", label=1, category="ignore_instruction", lang="ko"),
        EvalSample(text="정상", label=0, lang="ko"),
    ]
    path = tmp_path / "d.jsonl"
    save_jsonl(samples, path)

    assert load_jsonl(path) == samples


def test_rejects_invalid_label() -> None:
    with pytest.raises(ValueError, match="label"):
        EvalSample(text="x", label=2)


def test_attack_requires_category_absent_is_allowed() -> None:
    sample = EvalSample(text="x", label=1)
    assert sample.category is None


def test_skips_blank_lines(tmp_path) -> None:
    path = tmp_path / "d.jsonl"
    path.write_text(
        '{"text": "a", "label": 0, "lang": "ko", "source": "handcrafted"}\n\n',
        encoding="utf-8",
    )
    assert len(load_jsonl(path)) == 1
