"""Ограничение частоты запросов на пользователя.

Основная реализация — счётчик в Redis (окно 60 с). Если Redis недоступен,
используется процессный fallback, чтобы API не падал из-за лимитера.
"""

from __future__ import annotations

import threading
import time

from app.core.config import get_settings
from app.core.errors import RateLimited
from app.core.logging import get_logger

log = get_logger(__name__)

_local: dict[str, list[float]] = {}
_local_lock = threading.Lock()
_redis_client = None
_redis_failed_until = 0.0


def _redis():  # pragma: no cover - зависит от окружения
    global _redis_client, _redis_failed_until
    if time.time() < _redis_failed_until:
        return None
    if _redis_client is None:
        try:
            import redis

            _redis_client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=1)
            _redis_client.ping()
        except Exception as exc:
            log.warning("Redis для rate limit недоступен: %s", exc)
            _redis_client = None
            _redis_failed_until = time.time() + 30
    return _redis_client


def _local_hit(key: str, limit: int) -> None:
    now = time.time()
    with _local_lock:
        window = [t for t in _local.get(key, []) if now - t < 60]
        if len(window) >= limit:
            _local[key] = window
            raise RateLimited(f"Превышен лимит {limit} запросов в минуту", key=key)
        window.append(now)
        _local[key] = window


def check_rate_limit(subject: str, *, scope: str = "api", limit: int | None = None) -> None:
    """Бросает :class:`RateLimited`, если лимит превышен."""
    s = get_settings()
    limit = limit or s.rate_limit_requests_per_minute
    if limit <= 0:
        return
    key = f"ratelimit:{scope}:{subject}"
    client = _redis()
    if client is None:
        _local_hit(key, limit)
        return
    try:  # pragma: no cover - требует Redis
        pipe = client.pipeline()
        pipe.incr(key, 1)
        pipe.expire(key, 60)
        count = int(pipe.execute()[0])
    except Exception as exc:  # pragma: no cover
        log.warning("rate limit через Redis не сработал: %s", exc)
        _local_hit(key, limit)
        return
    if count > limit:
        raise RateLimited(f"Превышен лимит {limit} запросов в минуту", key=key)


def reset_rate_limits() -> None:
    with _local_lock:
        _local.clear()
