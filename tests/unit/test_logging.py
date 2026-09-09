"""Unit tests for structured logging."""

from __future__ import annotations

import io
import json
import logging

from c2forensics.logging import JsonFormatter, get_logger


def test_json_formatter_emits_single_object() -> None:
    logger = logging.getLogger("c2forensics.tests.json")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.info("hello", extra={"experiment_id": "EXP001", "score": 0.9})
    out = buf.getvalue().strip()
    payload = json.loads(out)
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "c2forensics.tests.json"
    assert payload["experiment_id"] == "EXP001"
    assert payload["score"] == 0.9
    assert "ts" in payload


def test_json_formatter_falls_back_to_repr_for_non_serialisable() -> None:
    logger = logging.getLogger("c2forensics.tests.json_nonjson")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.info("msg", extra={"obj": {1, 2, 3}})  # sets are not JSON-serialisable
    payload = json.loads(buf.getvalue().strip())
    assert isinstance(payload["obj"], str)


def test_get_logger_returns_named_logger() -> None:
    assert get_logger("foo").name == "foo"
