"""Structured JSON logging for the forensic framework.

We deliberately avoid heavyweight logging frameworks. ``logging`` from the
stdlib is sufficient for the framework's needs and keeps the dependency
surface minimal. The custom ``JsonFormatter`` produces one JSON object per
log record so that downstream tooling can ingest logs without further
parsing.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


_RESERVED_LOG_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Format ``LogRecord`` instances as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401 - stdlib override
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach any extra fields the caller passed via ``logger.info(..., extra=...)``.
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOG_KEYS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=False)


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger to emit JSON on stderr.

    Idempotent: safe to call from CLI entry points that may run more than
    once in a single process.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())
    # Remove any handlers a previous call may have installed.
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger; configuration is the caller's responsibility.

    Naming convention: ``c2forensics.<module>`` for all framework modules.
    """
    return logging.getLogger(name)
