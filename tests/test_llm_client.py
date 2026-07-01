from app.llm_client import _extract_output_text


def test_extract_output_text() -> None:
    response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "테스트 응답입니다."}
                    ]
                }
            }
        ]
    }

    assert _extract_output_text(response) == "테스트 응답입니다."
