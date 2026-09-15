"""Логи должны быть читаемыми и грепаемыми.

Проект логирует по-русски. `json.dumps` по умолчанию экранирует не-ASCII, и
тогда `docker compose logs` показывает `\\uXXXX` вместо текста, а `grep` по
русскому слову не находит строку никогда — ни при работающем сервисе, ни при
сломанном. На этом однажды уже сорвалась диагностика зависшей очереди.
"""

from __future__ import annotations

import json
import logging

from app.core.logging import configure_logging, get_logger


def _emit(caplog_stream, message: str, **extra) -> str:
    """Пишет строку настроенным форматтером и возвращает готовый JSON."""
    configure_logging("INFO")
    handler = logging.getLogger().handlers[0]
    record = logging.LogRecord(
        name="app.services.watchdog",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    record.request_id = "-"
    return handler.format(record)


def test_cyrillic_stays_readable():
    """Кириллица пишется как есть, а не как \\uXXXX."""
    line = _emit(None, "сторож очереди запущен")

    assert "сторож очереди запущен" in line
    assert "\\u0441" not in line


def test_log_line_is_greppable_by_russian_word():
    """Ровно то, что делает человек в консоли: grep по русскому слову."""
    line = _emit(None, "сторож очереди выключен (PIPELINE_WATCHDOG_ENABLED=false)")

    assert "сторож" in line  # grep -i сторож найдёт эту строку


def test_line_is_still_valid_json():
    """Читаемость не должна ломать структурность логов."""
    line = _emit(None, "пакет заявки не найден", item_id=42)

    payload = json.loads(line)
    assert payload["message"] == "пакет заявки не найден"
    assert payload["logger"] == "app.services.watchdog"
    assert payload["item_id"] == 42
    assert payload["level"] == "INFO"


def test_logger_name_is_ascii_anchor():
    """Имя логгера остаётся ASCII — по нему можно грепать независимо от языка сообщения."""
    line = _emit(None, "любое сообщение")

    assert "app.services.watchdog" in line


def test_get_logger_returns_configured_logger():
    configure_logging("INFO")
    assert get_logger("app.services.watchdog").name == "app.services.watchdog"
