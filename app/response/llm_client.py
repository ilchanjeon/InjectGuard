import httpx

from app.config import settings


class LLMClientError(Exception):
    """Gemini API configuration or response error."""


async def request_llm(message: str) -> str:
    if not settings.gemini_api_key:
        raise LLMClientError("GEMINI_API_KEY가 설정되지 않았습니다.")

    payload = {
        "contents": [
            {"parts": [{"text": message}]}
        ]
    }
    headers = {
        "x-goog-api-key": settings.gemini_api_key,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(
        timeout=settings.gemini_timeout_seconds
    ) as client:
        response = await client.post(
            settings.gemini_generate_url,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()

    result = response.json()
    output_text = _extract_output_text(result)
    if not output_text:
        raise LLMClientError(
            "Gemini API 응답에서 텍스트를 찾지 못했습니다."
        )
    return output_text


def _extract_output_text(result: dict) -> str:
    texts: list[str] = []
    for candidate in result.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = part.get("text")
            if text:
                texts.append(text)
    return "\n".join(texts).strip()
