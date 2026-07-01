from contextlib import asynccontextmanager
from time import perf_counter

import httpx
from fastapi import FastAPI, HTTPException

from app.audit import write_audit_log
from app.config import settings
from app.decision import make_decision
from app.detectors.embedding_detector import EmbeddingDetector
from app.detectors.rule_detector import RuleDetector
from app.llm_client import LLMClientError, request_llm
from app.preprocessing import preprocess
from app.schemas import ChatRequest, ChatResponse, HealthResponse


rule_detector: RuleDetector | None = None
embedding_detector: EmbeddingDetector | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global rule_detector, embedding_detector
    rule_detector = RuleDetector()
    embedding_detector = EmbeddingDetector()
    yield


app = FastAPI(
    title=settings.app_name,
    description="LLM 기반 서비스의 프롬프트 인젝션 공격 대응 보안 필터",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        detector_ready=(
            rule_detector is not None and embedding_detector is not None
        ),
    )


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    if rule_detector is None or embedding_detector is None:
        raise HTTPException(
            status_code=503,
            detail="탐지 모델을 준비하는 중입니다.",
        )

    started_at = perf_counter()
    normalized = preprocess(request.message)
    rule_score, matched_pattern = rule_detector.detect(normalized)
    embedding_score = embedding_detector.detect(normalized)
    decision = make_decision(
        rule_score=rule_score,
        embedding_score=embedding_score,
        matched_pattern=matched_pattern,
    )
    detection_time_ms = (perf_counter() - started_at) * 1000

    audit_record = {
        "status": "blocked" if decision.is_attack else "allowed",
        "reason": decision.reason,
        "rule_score": decision.rule_score,
        "embedding_score": decision.embedding_score,
        "matched_pattern": decision.matched_pattern,
        "detection_time_ms": detection_time_ms,
    }

    if decision.is_attack:
        write_audit_log(audit_record)
        return ChatResponse(
            status="blocked",
            response="보안 정책에 따라 요청이 차단되었습니다.",
            rule_score=decision.rule_score,
            embedding_score=decision.embedding_score,
            reason=decision.reason,
            detection_time_ms=detection_time_ms,
        )

    try:
        llm_response = await request_llm(request.message)
    except LLMClientError as error:
        write_audit_log({**audit_record, "status": "llm_config_error"})
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error
    except httpx.HTTPStatusError as error:
        write_audit_log(
            {
                **audit_record,
                "status": "llm_api_error",
                "http_status": error.response.status_code,
            }
        )
        raise HTTPException(
            status_code=502,
            detail="Gemini API가 요청을 거부했습니다. API 키와 모델명을 확인하세요.",
        ) from error
    except httpx.HTTPError as error:
        write_audit_log({**audit_record, "status": "llm_error"})
        raise HTTPException(
            status_code=502,
            detail="Gemini API 호출에 실패했습니다.",
        ) from error

    write_audit_log(audit_record)
    return ChatResponse(
        status="allowed",
        response=llm_response,
        rule_score=decision.rule_score,
        embedding_score=decision.embedding_score,
        reason=decision.reason,
        detection_time_ms=detection_time_ms,
    )


@app.post("/chat/raw", response_model=ChatResponse)
async def chat_raw(request: ChatRequest) -> ChatResponse:
    """Baseline endpoint that calls Gemini without InjectGuard filtering."""
    started_at = perf_counter()

    audit_record = {
        "status": "raw_allowed",
        "reason": "raw_baseline_no_filter",
        "rule_score": 0.0,
        "embedding_score": 0.0,
        "matched_pattern": None,
        "detection_time_ms": 0.0,
    }

    try:
        llm_response = await request_llm(request.message)
    except LLMClientError as error:
        write_audit_log({**audit_record, "status": "raw_llm_config_error"})
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error
    except httpx.HTTPStatusError as error:
        write_audit_log(
            {
                **audit_record,
                "status": "raw_llm_api_error",
                "http_status": error.response.status_code,
            }
        )
        raise HTTPException(
            status_code=502,
            detail="Gemini API가 요청을 거부했습니다. API 키와 모델명을 확인하세요.",
        ) from error
    except httpx.HTTPError as error:
        write_audit_log({**audit_record, "status": "raw_llm_error"})
        raise HTTPException(
            status_code=502,
            detail="Gemini API 호출에 실패했습니다.",
        ) from error

    elapsed_ms = (perf_counter() - started_at) * 1000
    write_audit_log({**audit_record, "response_time_ms": elapsed_ms})
    return ChatResponse(
        status="raw_allowed",
        response=llm_response,
        rule_score=0.0,
        embedding_score=0.0,
        reason="raw_baseline_no_filter",
        detection_time_ms=0.0,
    )
