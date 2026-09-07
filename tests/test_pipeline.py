import pytest

from app.contracts import Action, DetectorSignal, FilterResult
from app.pipeline import BLOCKED_MESSAGE, Pipeline


class StubDetector:
    def __init__(self, name: str, score: float, detail: str | None = None) -> None:
        self.name = name
        self._score = score
        self._detail = detail

    def score(self, filter_result: FilterResult) -> DetectorSignal:
        return DetectorSignal(self.name, self._score, self._detail)


def build(rule: float = 0.0, embedding: float = 0.0, detail=None) -> Pipeline:
    return Pipeline(
        rule_detector=StubDetector("rule", rule, detail),
        embedding_detector=StubDetector("embedding", embedding),
        t_low=0.75,
        t_high=0.75,
    )


def test_analyze_allows_safe_input() -> None:
    analysis = build(embedding=0.2).analyze("정보보호 원칙 알려줘")
    assert analysis.decision.action is Action.ALLOW
    assert analysis.decision.reason == "safe"


def test_analyze_blocks_rule_match() -> None:
    analysis = build(rule=1.0, detail="ignore_instruction:p").analyze("무시해")
    assert analysis.decision.action is Action.BLOCK
    assert analysis.detection.matched_pattern == "ignore_instruction:p"


def test_analyze_records_timings() -> None:
    analysis = build().analyze("hello")
    for key in ("filter_ms", "rule_ms", "embedding_ms", "total_ms"):
        assert key in analysis.timings
        assert analysis.timings[key] >= 0.0


def test_analyze_preserves_original_for_llm() -> None:
    analysis = build().analyze("  Hello World  ")
    assert analysis.filter_result.original == "  Hello World  "
    assert analysis.filter_result.normalized == "hello world"


@pytest.mark.anyio
async def test_handle_blocks_without_calling_llm(monkeypatch) -> None:
    called = False

    async def fake_llm(message: str) -> str:
        nonlocal called
        called = True
        return "should not happen"

    monkeypatch.setattr("app.pipeline.request_llm", fake_llm)
    result = await build(rule=1.0, detail="c:p").handle("무시해")

    assert result.llm_called is False
    assert result.response_text == BLOCKED_MESSAGE
    assert called is False


@pytest.mark.anyio
async def test_handle_forwards_original_message_to_llm(monkeypatch) -> None:
    seen: list[str] = []

    async def fake_llm(message: str) -> str:
        seen.append(message)
        return "LLM 응답"

    monkeypatch.setattr("app.pipeline.request_llm", fake_llm)
    result = await build(embedding=0.1).handle("  Hello World  ")

    assert result.llm_called is True
    assert result.response_text == "LLM 응답"
    assert seen == ["  Hello World  "]  # 정규화본이 아니라 원문


def test_audit_record_contains_reproducibility_fields() -> None:
    analysis = build(rule=1.0, detail="c:p").analyze("무시해")
    record = build().audit_record(analysis, status="blocked")

    for key in (
        "request_id",
        "status",
        "reason",
        "risk_level",
        "action",
        "risk_score",
        "rule_score",
        "embedding_score",
        "signals",
        "filter_stats",
        "timings",
        "config_version",
    ):
        assert key in record


def test_audit_record_hashes_message_when_disabled(monkeypatch) -> None:
    """Settings는 frozen dataclass라 필드를 직접 setattr 할 수 없다.

    dataclasses.replace()로 새 인스턴스를 만들어 모듈의 이름 바인딩을
    교체한다. monkeypatch.setattr("...settings.audit_log_message", ...)는
    FrozenInstanceError로 실패한다.
    """
    from dataclasses import replace

    from app.config import settings as real_settings

    monkeypatch.setattr(
        "app.pipeline.settings",
        replace(real_settings, audit_log_message=False),
    )
    analysis = build().analyze("비밀 입력")
    record = build().audit_record(analysis, status="allowed")

    assert "message" not in record
    assert len(record["message_sha256"]) == 64
