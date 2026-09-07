import hashlib
import uuid
from time import perf_counter
from typing import Any

import anyio.to_thread

from app.config import settings
from app.contracts import (
    Action,
    AnalysisResult,
    DetectionResult,
    HandleResult,
)
from app.detection.base import Detector
from app.filtering.normalizer import normalize
from app.response.llm_client import request_llm
from app.response.policy import decide


BLOCKED_MESSAGE = "보안 정책에 따라 요청이 차단되었습니다."


class Pipeline:
    """필터 → 탐지 → 대응 오케스트레이션.

    analyze()는 동기·순수·LLM 없음이라 평가 하니스가 배치로 호출할 수 있다.
    handle()은 analyze() 전체를 워커 스레드로 넘겨 이벤트 루프 블로킹을 막는다.
    """

    def __init__(
        self,
        rule_detector: Detector,
        embedding_detector: Detector,
        t_low: float | None = None,
        t_high: float | None = None,
    ) -> None:
        self.rule_detector = rule_detector
        self.embedding_detector = embedding_detector
        self.t_low = settings.risk_threshold_low if t_low is None else t_low
        self.t_high = settings.risk_threshold_high if t_high is None else t_high

    def analyze(self, message: str) -> AnalysisResult:
        started = perf_counter()

        mark = perf_counter()
        filter_result = normalize(message)
        filter_ms = (perf_counter() - mark) * 1000

        mark = perf_counter()
        rule_signal = self.rule_detector.score(filter_result)
        rule_ms = (perf_counter() - mark) * 1000

        mark = perf_counter()
        embedding_signal = self.embedding_detector.score(filter_result)
        embedding_ms = (perf_counter() - mark) * 1000

        detection = DetectionResult(
            signals=(rule_signal, embedding_signal),
            rule_score=rule_signal.score,
            embedding_score=embedding_signal.score,
            evasion_score=0.0,
            matched_pattern=rule_signal.detail,
        )
        decision = decide(detection, self.t_low, self.t_high)

        return AnalysisResult(
            filter_result=filter_result,
            detection=detection,
            decision=decision,
            timings={
                "filter_ms": filter_ms,
                "rule_ms": rule_ms,
                "embedding_ms": embedding_ms,
                "total_ms": (perf_counter() - started) * 1000,
            },
        )

    async def handle(self, message: str) -> HandleResult:
        analysis = await anyio.to_thread.run_sync(self.analyze, message)

        if analysis.decision.action is Action.BLOCK:
            return HandleResult(
                analysis=analysis,
                response_text=BLOCKED_MESSAGE,
                llm_called=False,
            )

        # Phase 0에서는 SANITIZE 구간이 비어 있으므로 원문을 그대로 전달한다.
        # 무해화는 Phase 3에서 sanitizer 도입과 함께 여기에 들어간다.
        response_text = await request_llm(analysis.filter_result.original)
        return HandleResult(
            analysis=analysis,
            response_text=response_text,
            llm_called=True,
        )

    def audit_record(
        self,
        analysis: AnalysisResult,
        status: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        message = analysis.filter_result.original
        record: dict[str, Any] = {
            "request_id": str(uuid.uuid4()),
            "status": status,
            "reason": analysis.decision.reason,
            "risk_level": str(analysis.decision.risk_level),
            "action": str(analysis.decision.action),
            "risk_score": analysis.decision.risk_score,
            "rule_score": analysis.detection.rule_score,
            "embedding_score": analysis.detection.embedding_score,
            "matched_pattern": analysis.decision.evidence.get("matched_pattern"),
            "signals": {s.name: s.score for s in analysis.detection.signals},
            "filter_stats": {
                "removed_invisible": analysis.filter_result.removed_invisible,
                "homoglyphs_folded": analysis.filter_result.homoglyphs_folded,
                "flags": list(analysis.filter_result.flags),
            },
            "timings": analysis.timings,
            "config_version": settings.config_version,
        }

        if settings.audit_log_message:
            record["message"] = message
        else:
            record["message_sha256"] = hashlib.sha256(
                message.encode("utf-8")
            ).hexdigest()

        if extra:
            record.update(extra)
        return record
