"""
Structured (JSON) logging with per-request correlation IDs.

Why this over structlog/python-json-logger: stdlib `logging` plus a
`ContextVar` covers the actual requirement — every log line tagged with a
request_id, valid JSON, no new dependency — without pulling in a library for
something this small. The ContextVar means request_id automatically appears
on every log call made anywhere during a request's lifetime (services,
routers, background helpers called from a request), not just ones that
explicitly pass it through as an argument.

Background jobs (the APScheduler jobs in main.py) run outside any request,
so request_id is simply absent from their log lines — that's expected, not
a bug; they're correlated by job name and timestamp instead.
"""
from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_RESERVED = frozenset(logging.LogRecord(
    "", 0, "", 0, "", (), None,
).__dict__.keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Anything passed via logging's `extra={...}` kwarg shows up as plain
        # attributes on the record — surface those too instead of dropping them.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in payload:
                payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
