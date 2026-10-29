"""Structured JSON application logging. Evidence content must never be logged."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

_CONTEXT_FIELDS = ("request_id", "job_id", "case_id", "run_id", "error_code")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for name in _CONTEXT_FIELDS:
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Uvicorn's access log would duplicate request lines in a second format.
    logging.getLogger("uvicorn.access").disabled = True
