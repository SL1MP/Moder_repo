"""Диагностика очереди: команда должна называть причину, а не только симптом.

Проверяем, что `queue-doctor` различает состояния, которые снаружи выглядят
одинаково («пакет вечно проверяется»), но лечатся по-разному: worker не
запущен, worker жив но молчит heartbeat'ом, и — самое неочевидное — worker жив,
однако слушает не те очереди.
"""

from __future__ import annotations

import time

import pytest

from app.core.config import get_settings
from app.services import queue_doctor, worker_health
from app.services.queue_doctor import KNOWN_QUEUES, diagnose, format_report

pytestmark = pytest.mark.usefixtures(
    "policies", "store", "storage", "vuln_index", "notifier", "fake_metadata"
)


class FakeRedis:
    """Часть Redis, нужная heartbeat'у и подсчёту длины очередей."""

    def __init__(self, depths: dict[str, int] | None = None) -> None:
        self.values: dict[str, str] = {}
        self.depths = depths or {}
        self.fail = False

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        if self.fail:
            raise ConnectionError("Redis недоступен (тест)")
        self.values[key] = value

    def get(self, key: str) -> str | None:
        if self.fail:
            raise ConnectionError("Redis недоступен (тест)")
        return self.values.get(key)

    def delete(self, key: str) -> None:
        self.values.pop(key, None)

    def llen(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("Redis недоступен (тест)")
        return self.depths.get(key, 0)


@pytest.fixture
def fake_redis(monkeypatch):
    client = FakeRedis()
    # Два разных шва: heartbeat живёт в REDIS_URL, очередь мерится по
    # CELERY_BROKER_URL. В тестах за обоими стоит один и тот же фейк.
    monkeypatch.setattr(worker_health, "_redis", lambda: client)
    monkeypatch.setattr(queue_doctor, "_broker_client", lambda: client)
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", False)
    return client


def _alive(client: FakeRedis) -> None:
    """Свежий heartbeat — API считает worker'а живым."""
    client.values[worker_health.HEARTBEAT_KEY] = str(time.time())


def _inspect(monkeypatch, result):
    """Подменяет опрос worker'ов: result — что вернул `active_queues()`."""

    def fake_inspect():
        if isinstance(result, Exception):
            raise result
        if not result:
            return False, "ни один worker не ответил на inspect", {}
        consumed = {node: sorted(queues) for node, queues in result.items()}
        return True, f"ответили worker'ы: {', '.join(sorted(consumed))}", consumed

    monkeypatch.setattr(queue_doctor, "_inspect_workers", fake_inspect)


def test_eager_mode_needs_no_worker(fake_redis, monkeypatch, session):
    """В eager-режиме конвейер идёт в самом API — жаловаться не на что."""
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", True)

    report = diagnose()

    assert report.healthy
    assert "синхронно" in report.verdict
    assert report.hints == []


def test_broker_down_is_reported_first(fake_redis, monkeypatch, session):
    """Без Redis складывать задачи некуда — это и есть причина."""
    fake_redis.fail = True
    _inspect(monkeypatch, {})

    report = diagnose()

    assert not report.broker_ok
    assert not report.healthy
    assert "Redis недоступен" in report.verdict
    assert any("docker compose up -d redis" in hint for hint in report.hints)


def test_worker_absent_points_at_container_logs(fake_redis, monkeypatch, session):
    """Ни heartbeat, ни ответа на inspect — worker'а просто нет."""
    fake_redis.depths = {"moderation": 3, "maintenance": 0}
    _inspect(monkeypatch, {})

    report = diagnose()

    assert not report.worker.alive
    assert not report.inspect_ok
    assert "не запущен" in report.verdict
    assert any("logs worker" in hint for hint in report.hints)
    assert report.queue_depths["moderation"] == 3


def test_alive_worker_without_heartbeat_is_distinguished(fake_redis, monkeypatch, session):
    """Worker отвечает, но heartbeat молчит — лечится пересборкой, а не рестартом Redis."""
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})

    report = diagnose()

    assert report.inspect_ok
    assert not report.worker.alive
    assert "heartbeat" in report.verdict
    assert any("--build worker" in hint for hint in report.hints)


def test_queue_nobody_listens_to_is_the_root_cause(fake_redis, monkeypatch, session):
    """Живой worker, слушающий не те очереди, — задачи уходят в никуда."""
    _alive(fake_redis)
    fake_redis.depths = {"moderation": 7, "maintenance": 0}
    _inspect(monkeypatch, {"celery@worker1": ["maintenance"]})

    report = diagnose()

    assert report.worker.alive
    assert "moderation" in report.verdict
    assert any("CELERY_QUEUES" in hint for hint in report.hints)


def test_idle_broker_with_stuck_item_points_at_watchdog(
    fake_redis, monkeypatch, session, users
):
    """Очереди пусты, worker жив, пакет висит — значит, задачу никто не отправляет.

    Реальный случай с заявкой #9: класть сообщение было бы некуда, поэтому
    «потерялось сообщение» тут не объяснение — сторож не делает проходы.
    """
    _alive(fake_redis)
    fake_redis.depths = {"moderation": 0, "maintenance": 0}
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})
    monkeypatch.setattr(queue_doctor, "find_stuck", lambda *a, **k: [9], raising=False)
    monkeypatch.setattr(
        "app.services.watchdog.find_stuck", lambda *a, **k: [9], raising=False
    )

    report = diagnose()

    assert report.stuck == [9]
    assert "сторож не делает проходы" in report.verdict
    assert any("logs api" in hint for hint in report.hints)


def test_backlog_with_stuck_item_reads_as_lost_message(fake_redis, monkeypatch, session):
    """А вот при непустой очереди объяснение другое — сообщение действительно могло потеряться."""
    _alive(fake_redis)
    fake_redis.depths = {"moderation": 4, "maintenance": 0}
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})
    monkeypatch.setattr(
        "app.services.watchdog.find_stuck", lambda *a, **k: [9], raising=False
    )

    report = diagnose()

    assert "сообщение потерялось" in report.verdict
    assert not any("logs api" in hint for hint in report.hints)


def test_publish_route_mismatch_is_named(fake_redis, monkeypatch, session):
    """Задача уходит в очередь, которую никто не слушает.

    Ни heartbeat, ни `inspect` такого не ловят: worker жив и честно слушает
    свои очереди — просто не ту, в которую публикуют.
    """
    _alive(fake_redis)
    monkeypatch.setattr(queue_doctor, "_publish_route", lambda: ("redis://redis:6379/0", "pipeline"))
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})

    report = diagnose()

    assert "pipeline" in report.verdict
    assert any("task_routes" in hint for hint in report.hints)


def test_broker_depth_is_measured_on_broker_url(monkeypatch, session):
    """Длину очереди меряем по CELERY_BROKER_URL, а не по REDIS_URL.

    Настройки разные; при расхождении отчёт показывал бы ноль, пока сообщения
    копятся у другого брокера.
    """
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", False)
    monkeypatch.setattr(get_settings(), "redis_url", "redis://redis:6379/7")
    monkeypatch.setattr(get_settings(), "celery_broker_url", "redis://redis:6379/0")

    seen: list[str] = []

    def fake_from_url(url, **_kwargs):
        seen.append(url)
        return FakeRedis({"moderation": 5})

    import redis

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(fake_from_url))

    ok, detail, depths = queue_doctor._queue_depths()

    assert ok
    assert seen == ["redis://redis:6379/0"]  # брокер, а не redis_url
    assert depths["moderation"] == 5
    assert "6379/0" in detail


def test_broker_password_is_masked_in_report():
    """Отчёт пересылают целиком — пароль брокера в нём не нужен."""
    masked = queue_doctor.mask_url("redis://user:s3cret@redis:6379/0")

    assert "s3cret" not in masked
    assert "user" in masked and "redis:6379/0" in masked


def test_partial_coverage_is_not_flagged(fake_redis, monkeypatch, session):
    """Очередь слушает хотя бы один worker — это не поломка."""
    _alive(fake_redis)
    _inspect(
        monkeypatch,
        {"celery@worker1": ["moderation"], "celery@worker2": ["maintenance"]},
    )

    report = diagnose()

    assert report.healthy
    assert "штатно" in report.verdict


def test_healthy_queue_reports_no_hints(fake_redis, monkeypatch, session):
    """Всё в порядке — команда не должна выдумывать проблему."""
    _alive(fake_redis)
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})

    report = diagnose()

    assert report.healthy
    assert report.hints == []
    assert "штатно" in report.verdict


def test_inspect_failure_does_not_crash_diagnosis(fake_redis, monkeypatch, session):
    """Сломавшийся inspect не должен ронять саму диагностику — проверяем настоящую функцию."""
    from app.tasks.celery_app import celery_app

    def boom(*_args, **_kwargs):
        raise RuntimeError("broker refused")

    monkeypatch.setattr(celery_app.control, "inspect", boom)

    report = diagnose()

    assert not report.inspect_ok
    assert "broker refused" in report.inspect_detail
    assert report.verdict  # вывод всё равно сформирован


def test_report_is_copy_pasteable(fake_redis, monkeypatch, session):
    """Отчёт печатается целиком: и данные, и вывод."""
    _alive(fake_redis)
    fake_redis.depths = {"moderation": 2, "maintenance": 1}
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})

    text = format_report(diagnose())

    assert "=== Диагностика очереди ===" in text
    assert "длина очередей" in text
    assert "moderation=2" in text
    assert "celery@worker1 слушает" in text
    assert "ВЫВОД:" in text


def test_report_serialises_for_api(fake_redis, monkeypatch, session):
    """to_dict отдаёт всё, что нужно UI и /system/status."""
    _alive(fake_redis)
    _inspect(monkeypatch, {"celery@worker1": list(KNOWN_QUEUES)})

    data = diagnose().to_dict()

    assert set(data) >= {"worker", "queue_depths", "consumed_queues", "verdict", "healthy"}
    assert data["healthy"] is True
