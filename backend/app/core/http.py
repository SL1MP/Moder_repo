"""HTTP-клиент для всех внешних вызовов: явный прокси, таймауты, ретраи, circuit breaker.

Прокси задаётся явно из настроек (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`), а не через
неявное чтение переменных окружения библиотекой — так поведение одинаково в API,
worker и тестах.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.errors import CircuitOpenError, UpstreamError
from app.core.logging import get_logger
from app.core.metrics import circuit_state, external_call_total

log = get_logger(__name__)

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


@dataclass
class CircuitBreaker:
    """Простой circuit breaker на процесс.

    Пороги читаются из настроек при каждом вызове, чтобы правка `.env` и рестарт
    (а в тестах — подмена настроек) применялись без пересоздания объекта.
    """

    name: str
    _failures: int = 0
    _opened_at: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def fail_max(self) -> int:
        return get_settings().circuit_breaker_fail_max

    @property
    def reset_seconds(self) -> float:
        return float(get_settings().circuit_breaker_reset_seconds)

    def _set_metric(self, value: int) -> None:
        circuit_state.labels(service=self.name).set(value)

    def before_call(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if time.monotonic() - self._opened_at >= self.reset_seconds:
                self._opened_at = None
                self._failures = 0
                self._set_metric(2)  # half-open: пробный вызов
                return
        raise CircuitOpenError(
            f"Обращения к «{self.name}» временно приостановлены (circuit breaker)",
            service=self.name,
        )

    def on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
        self._set_metric(0)

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.fail_max:
                self._opened_at = time.monotonic()
                self._set_metric(1)
                log.warning("circuit breaker открыт", extra={"service": self.name})

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
        self._set_metric(0)


_breakers: dict[str, CircuitBreaker] = {}
_breakers_lock = threading.Lock()


def get_breaker(name: str) -> CircuitBreaker:
    with _breakers_lock:
        br = _breakers.get(name)
        if br is None:
            br = CircuitBreaker(name=name)
            _breakers[name] = br
        return br


def reset_all_breakers() -> None:
    """Сбрасывает счётчики и забывает созданные breaker'ы (используется в тестах)."""
    with _breakers_lock:
        for br in _breakers.values():
            br.reset()
        _breakers.clear()


def _no_proxy_mounts() -> dict[str, httpx.BaseTransport | None]:
    """Хосты из NO_PROXY обслуживаем транспортом без прокси.

    NO_PROXY в реальных окружениях содержит и то, что httpx-паттернами не выразить
    (CIDR-подсети, IPv6, `host:port`). Такие записи пропускаем с предупреждением,
    вместо того чтобы падать при создании клиента.
    """
    mounts: dict[str, httpx.BaseTransport | None] = {}
    direct = httpx.HTTPTransport(proxy=None, retries=0)
    for raw in get_settings().no_proxy_hosts:
        host = raw.strip().lstrip(".")
        if not host:
            continue
        if host == "*":  # прокси отключён полностью
            return {"all://": direct}
        if "/" in host or ":" in host:
            # CIDR-подсеть, IPv6-адрес или host:port — httpx такие паттерны не принимает.
            log.debug("запись NO_PROXY пропущена: %s", raw)
            continue
        for pattern in (f"http://{host}", f"https://{host}", f"http://*.{host}", f"https://*.{host}"):
            try:
                httpx._utils.URLPattern(pattern)  # noqa: SLF001 - валидация паттерна
            except Exception:  # noqa: BLE001 - некорректная запись просто пропускается
                log.debug("паттерн NO_PROXY отброшен: %s", pattern)
                continue
            mounts[pattern] = direct
    return mounts


def build_client(*, use_proxy: bool = True, timeout: float | None = None, **kwargs: Any) -> httpx.Client:
    """httpx.Client с корпоративным прокси и уважением NO_PROXY."""
    s = get_settings()
    mounts: dict[str, httpx.BaseTransport | None] = {}
    if use_proxy:
        mounts.update(_no_proxy_mounts())
        for prefix, proxy_url in s.proxies.items():
            mounts.setdefault(prefix, httpx.HTTPTransport(proxy=proxy_url, retries=0))
    return httpx.Client(
        timeout=timeout or s.http_timeout_seconds,
        mounts=mounts or None,
        follow_redirects=True,
        trust_env=False,
        **kwargs,
    )


@contextmanager
def client(**kwargs: Any) -> Iterator[httpx.Client]:
    c = build_client(**kwargs)
    try:
        yield c
    finally:
        c.close()


def request_with_retries(
    service: str,
    call: Callable[[], httpx.Response],
    *,
    retries: int | None = None,
    retry_status: set[int] | None = None,
) -> httpx.Response:
    """Выполняет вызов с ретраями (экспоненциальная пауза + jitter) под circuit breaker."""
    s = get_settings()
    attempts = (retries if retries is not None else s.http_retries) + 1
    statuses = retry_status if retry_status is not None else RETRY_STATUS
    breaker = get_breaker(service)
    last_exc: Exception | None = None

    for attempt in range(attempts):
        breaker.before_call()
        try:
            resp = call()
        except httpx.HTTPError as exc:
            last_exc = exc
            breaker.on_failure()
            external_call_total.labels(service=service, outcome="error").inc()
        else:
            if resp.status_code in statuses:
                breaker.on_failure()
                external_call_total.labels(service=service, outcome=f"http_{resp.status_code}").inc()
                last_exc = UpstreamError(
                    f"Внешний сервис «{service}» ответил {resp.status_code}",
                    service=service,
                    status=resp.status_code,
                )
            else:
                breaker.on_success()
                external_call_total.labels(service=service, outcome="ok").inc()
                return resp
        if attempt < attempts - 1:
            time.sleep(min(2**attempt, 8) * (0.5 + random.random() / 2))  # noqa: S311

    if isinstance(last_exc, UpstreamError):
        raise last_exc
    raise UpstreamError(
        f"Не удалось обратиться к внешнему сервису «{service}»: {last_exc}", service=service
    ) from last_exc


__all__ = [
    "CircuitBreaker",
    "build_client",
    "client",
    "get_breaker",
    "request_with_retries",
    "reset_all_breakers",
]
