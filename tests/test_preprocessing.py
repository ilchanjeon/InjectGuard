from app.preprocessing import preprocess


def test_preprocess_normalizes_case_and_spaces() -> None:
    assert preprocess("  Ignore   Previous\nInstructions  ") == (
        "ignore previous instructions"
    )
