from collections import Counter
from pathlib import Path

from eval.datasets.schema import load_jsonl

DATASET = Path(__file__).resolve().parent.parent / "eval" / "datasets" / "ko_eval.jsonl"


def test_dataset_exists_and_parses() -> None:
    assert DATASET.exists()
    assert len(load_jsonl(DATASET)) == 50


def test_label_balance() -> None:
    counts = Counter(s.label for s in load_jsonl(DATASET))
    assert counts[1] == 30
    assert counts[0] == 20


def test_all_five_categories_present() -> None:
    categories = {s.category for s in load_jsonl(DATASET) if s.label == 1}
    assert categories == {
        "ignore_instruction",
        "prompt_leakage",
        "role_jailbreak",
        "policy_bypass",
        "obfuscation",
    }


def test_benign_samples_have_no_category() -> None:
    assert all(s.category is None for s in load_jsonl(DATASET) if s.label == 0)


def test_contains_hard_negatives_that_current_rules_flag() -> None:
    """규칙이 오탐하는 정상 문장이 실제로 들어 있어야 FPR이 의미를 갖는다."""
    from app.detection.rule_detector import RuleDetector
    from app.filtering.normalizer import normalize

    detector = RuleDetector()
    false_positives = [
        s
        for s in load_jsonl(DATASET)
        if s.label == 0 and detector.score(normalize(s.text)).score > 0
    ]
    assert len(false_positives) >= 5
