from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=5000,
        description="LLM에 전달할 사용자 입력",
    )


class ChatResponse(BaseModel):
    status: str
    response: str
    rule_score: float
    embedding_score: float
    reason: str
    detection_time_ms: float


class HealthResponse(BaseModel):
    status: str
    detector_ready: bool
