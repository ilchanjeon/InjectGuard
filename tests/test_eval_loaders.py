import pytest

from eval.datasets.loaders import DatasetUnavailable, load_all, load_deepset, load_korean


def test_load_korean_returns_50_samples() -> None:
    assert len(load_korean()) == 50


def test_load_all_without_public_or_augmented() -> None:
    samples = load_all(include_public=False, include_augmented=False)
    assert len(samples) == 50


def test_load_all_with_augmented_adds_variants() -> None:
    samples = load_all(include_public=False, include_augmented=True)
    # 공격 30건 × 변형 4종 = 120건 추가
    assert len(samples) == 50 + 120
    assert any(s.source == "augmented" for s in samples)


def test_load_deepset_wraps_failure_with_cause(monkeypatch) -> None:
    """네트워크·인증 실패의 원인이 메시지에 드러나야 디버깅이 가능하다."""
    import datasets

    def boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(datasets, "load_dataset", boom)
    with pytest.raises(DatasetUnavailable, match="network down"):
        load_deepset()
