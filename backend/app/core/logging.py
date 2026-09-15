"""Структурные логи JSON с request_id."""

from __future__ import annotations

import logging
import sys
import uuid
from contextvars import ContextVar

from pythonjsonlogger import jsonlogger

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    return uuid.uuid4().hex


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.request_id = request_id_var.get()
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(request_id)s %(message)s",
            rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
            # Без этого json.dumps экранирует кириллицу в \uXXXX: сообщения в
            # `docker compose logs` становятся нечитаемыми, а grep по русскому
            # слову не находит их никогда — ни при работающем сервисе, ни при
            # сломанном. Логи проекта на русском, поэтому пишем их как есть.
            json_ensure_ascii=False,
        )
    )
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(noisy).setLevel("WARNING")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
