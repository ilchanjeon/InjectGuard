from app.contracts import FilterResult
from app.filtering.normalizer import normalize


def test_normalizes_case_and_spaces() -> None:
    result = normalize("  Ignore   Previous\nInstructions  ")
    assert result.normalized == "ignore previous instructions"


def test_keeps_original_untouched() -> None:
    raw = "  Ignore   Previous  "
    assert normalize(raw).original == raw


def test_returns_filter_result_with_phase0_defaults() -> None:
    result = normalize("hello")
    assert isinstance(result, FilterResult)
    assert result.variants == ()
    assert result.removed_invisible == 0
    assert result.homoglyphs_folded == 0
    assert result.flags == ()


def test_nfkc_folds_fullwidth() -> None:
    assert normalize("ＩＧＮＯＲＥ").normalized == "ignore"
