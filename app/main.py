from contextlib import asynccontextmanager
from time import perf_counter

import httpx
from fastapi import FastAPI, HTTPException, Request

from app.config import settings
from app.detection.embedding_detector import EmbeddingDetector
from app.detection.rule_detector import RuleDetector
from app.pipeline import Pipeline
from app.response.audit import write_audit_log
from app.response.llm_client import LLMClientError, request_llm
from app.schemas import ChatRequest, ChatResponse, HealthResponse


def build_pipeline() -> Pipeline:
    """실행용 파이프라인을 만든다. 테스트는 이 함수를 monkeypatch 한다."""
    return Pipeline(
        rule_detector=RuleDetector(),
        embedding_detector=EmbeddingDetector(),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pipeline = build_pipeline()
    yield


app = FastAPI(
    title=settings.app_name,
    description="LLM 기반 서비스의 프롬프트 인젝션 공격 대응 보안 필터",
    version="0.3.0",
    lifespan=lifespan,
)


def get_pipeline(request: Request) -> Pipeline:
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        raise HTTPException(status_code=503, detail="탐지 모델을 준비하는 중입니다.")
    return pipeline


@app.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    return HealthResponse(
        status="ok",
        detector_ready=getattr(request.app.state, "pipeline", None) is not None,
    )


@app.post("/chat", response_model=ChatResponse)
async def chat(request: Request, body: ChatRequest) -> ChatResponse:
    pipeline = get_pipeline(request)

    try:
        result = await pipeline.handle(body.message)
    except LLMClientError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except httpx.HTTPStatusError as error:
        raise HTTPException(
            status_code=502,
            detail="Gemini API가 요청을 거부했습니다. API 키와 모델명을 확인하세요.",
        ) from error
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=502,
            detail="Gemini API 호출에 실패했습니다.",
        ) from error

    analysis = result.analysis
    status = "allowed" if result.llm_called else "blocked"
    write_audit_log(pipeline.audit_record(analysis, status=status))

    return ChatResponse(
        status=status,
        response=result.response_text,
        rule_score=analysis.detection.rule_score,
        embedding_score=analysis.detection.embedding_score,
        reason=analysis.decision.reason,
        detection_time_ms=analysis.timings["total_ms"],
    )


@app.post("/chat/raw", response_model=ChatResponse)
async def chat_raw(body: ChatRequest) -> ChatResponse:
    """InjectGuard 필터링을 거치지 않는 baseline 엔드포인트.

    라우트는 항상 등록하되 요청 시점에 설정을 확인한다. 등록 자체를
    조건부로 하면 설정 변경이 import 시점에 고정되어 테스트가 불가능해진다.
    """
    if not settings.enable_raw_endpoint:
        raise HTTPException(status_code=404, detail="Not Found")

    started = perf_counter()
    try:
        llm_response = await request_llm(body.message)
    except LLMClientError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=502,
            detail="Gemini API 호출에 실패했습니다.",
        ) from error

    elapsed_ms = (perf_counter() - started) * 1000
    write_audit_log(
        {
            "status": "raw_allowed",
            "reason": "raw_baseline_no_filter",
            "response_time_ms": elapsed_ms,
            "config_version": settings.config_version,
        }
    )
    return ChatResponse(
        status="raw_allowed",
        response=llm_response,
        rule_score=0.0,
        embedding_score=0.0,
        reason="raw_baseline_no_filter",
        detection_time_ms=0.0,
    )
