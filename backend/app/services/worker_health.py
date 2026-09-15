"""Живость Celery-worker: heartbeat в Redis, отчёт для API и сторожа конвейера.

Раньше молчаливо упавший worker выглядел как «пакет вечно проверяется»: заявка
создавалась, задача уходила в Redis и там оставалась. Теперь worker раз в
`WORKER_HEARTBEAT_INTERVAL_SECONDS` обновляет ключ с TTL, а API по этому ключу
понимает, есть ли кому разбирать очередь.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

HEARTBEAT_KEY = "moderation:worker:heartbeat"

_client = None
_thread: threading.Thread | None = None
_stop = threading.Event()


def _redis():
    """Клиент Redis с короткими таймаутами: недоступность брокера — не повод виснуть."""
    global _client
    if _client is None:
        import redis  # локальный импорт: в тестах модуль подменяется целиком

        _client = redis.Redis.from_url(
            get_settings().redis_url,
            socket_timeout=2,
            socket_connect_timeout=2,
            decode_responses=True,
        )
    return _client


def reset_client() -> None:
    """Сбросить закешированный клиент (тесты, смена настроек)."""
    global _client
    _client = None


@dataclass(frozen=True)
class WorkerStatus:
    alive: bool
    detail: str
    last_seen: datetime | None = None
    age_seconds: float | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "alive": self.alive,
            "detail": self.detail,
            "last_seen": self.last_seen,
            "age_seconds": round(self.age_seconds, 1) if self.age_seconds is not None else None,
        }


def touch_heartbeat() -> bool:
    """Отметить, что worker жив. Возвращает False, если Redis недоступен."""
    s = get_settings()
    try:
        _redis().set(HEARTBEAT_KEY, str(time.time()), ex=s.worker_heartbeat_ttl_seconds)
        return True
    except Exception as exc:  # noqa: BLE001 - heartbeat не должен ронять worker
        log.warning("не удалось записать heartbeat worker: %s", exc)
        return False


def clear_heartbeat() -> None:
    try:
        _redis().delete(HEARTBEAT_KEY)
    except Exception as exc:  # noqa: BLE001
        log.debug("не удалось удалить heartbeat worker: %s", exc)


def worker_status() -> WorkerStatus:
    """Есть ли живой worker, разбирающий очередь."""
    s = get_settings()
    if s.celery_task_always_eager:
        # Задачи выполняются в самом API — отдельный worker не нужен.
        return WorkerStatus(alive=True, detail="задачи выполняются синхронно (eager-режим)")
    try:
        raw = _redis().get(HEARTBEAT_KEY)
    except Exception as exc:  # noqa: BLE001
        return WorkerStatus(alive=False, detail=f"Redis недоступен: {exc}")
    if not raw:
        return WorkerStatus(
            alive=False,
            detail="worker ни разу не отметился — проверьте контейнер worker",
        )
    try:
        seen = float(raw)
    except (TypeError, ValueError):
        return WorkerStatus(alive=False, detail="некорректная отметка heartbeat")
    age = max(0.0, time.time() - seen)
    last_seen = datetime.fromtimestamp(seen, UTC)
    if age > s.worker_heartbeat_ttl_seconds:
        return WorkerStatus(
            alive=False,
            detail=f"worker молчит {int(age)} с — очередь никто не разбирает",
            last_seen=last_seen,
            age_seconds=age,
        )
    return WorkerStatus(
        alive=True, detail="worker разбирает очередь", last_seen=last_seen, age_seconds=age
    )


def _loop() -> None:  # pragma: no cover - тело фонового потока
    interval = max(1, get_settings().worker_heartbeat_interval_seconds)
    while not _stop.is_set():
        touch_heartbeat()
        _stop.wait(interval)


def start_heartbeat_thread() -> threading.Thread | None:
    """Запускает фоновый поток heartbeat внутри процесса worker."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    _stop.clear()
    touch_heartbeat()  # первая отметка сразу, чтобы API не считал worker мёртвым
    _thread = threading.Thread(target=_loop, name="worker-heartbeat", daemon=True)
    _thread.start()
    return _thread


def stop_heartbeat_thread() -> None:
    _stop.set()
    clear_heartbeat()
