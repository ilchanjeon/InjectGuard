import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import BASE_DIR


LOG_PATH = BASE_DIR / "logs" / "audit.jsonl"


def write_audit_log(data: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    with LOG_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")
