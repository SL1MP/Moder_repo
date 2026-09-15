"""Сторож очереди: пакет не должен ждать ручного `moderctl run-pending`.

Проверяем три вещи, из-за которых заявка раньше висела в статусе «в очереди»:
живой worker виден по heartbeat, зависший пакет находится, и его прогоняет либо
переотправленная задача, либо сам сторож — но ровно один раз.
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import RequestItem
from app.pipeline.claim import claim_item, stale_running_seconds
from app.services import watchdog, worker_health
from tests.factories import make_request

pytestmark = pytest.mark.usefixtures(
    "policies", "store", "storage", "vuln_index", "notifier", "fake_metadata"
)


class FakeRedis:
    """Ровно та часть Redis, которой пользуется heartbeat."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
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


@pytest.fixture
def fake_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(worker_health, "_redis", lambda: client)
    # В тестах eager-режим включён, но проверяем именно логику heartbeat.
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", False)
    return client


def _make_stuck(session, users, *, seconds: int, status: str = "queued") -> RequestItem:
    """Заявка, чей пакет «висит» в очереди дольше порога."""
    _, item = make_request(session, users["developer"])
    item.status = status
    item.updated_at = utcnow() - timedelta(seconds=seconds)
    session.commit()
    return item


# ------------------------------------------------------------------ heartbeat
def test_worker_alive_after_heartbeat(fake_redis):
    assert worker_health.touch_heartbeat() is True
    status = worker_health.worker_status()
    assert status.alive is True
    assert status.last_seen is not None


def test_worker_dead_without_heartbeat(fake_redis):
    status = worker_health.worker_status()
    assert status.alive is False
    assert "ни разу" in status.detail


def test_worker_dead_when_heartbeat_expired(fake_redis, monkeypatch):
    monkeypatch.setattr(get_settings(), "worker_heartbeat_ttl_seconds", 30)
    fake_redis.values[worker_health.HEARTBEAT_KEY] = str(time.time() - 120)
    status = worker_health.worker_status()
    assert status.alive is False
    assert status.age_seconds is not None and status.age_seconds > 30


def test_worker_status_survives_broken_redis(fake_redis):
    fake_redis.fail = True
    status = worker_health.worker_status()
    assert status.alive is False
    assert "Redis недоступен" in status.detail
    # И запись heartbeat тоже не должна ронять worker.
    assert worker_health.touch_heartbeat() is False


def test_eager_mode_counts_as_alive(monkeypatch):
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", True)
    assert worker_health.worker_status().alive is True


# ---------------------------------------------------------------- поиск зависших
def test_find_stuck_ignores_fresh_items(session, users, monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    make_request(session, users["developer"])  # только что создан
    assert watchdog.find_stuck(session, include_running=False) == []


def test_find_stuck_finds_old_queued(session, users, monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=600)
    assert watchdog.find_stuck(session, include_running=False) == [item.id]


def test_find_stuck_takes_running_only_when_asked(session, users, monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=3600, status="running")
    assert watchdog.find_stuck(session, include_running=False) == []
    assert watchdog.find_stuck(session, include_running=True) == [item.id]


def test_find_stuck_keeps_fresh_running(session, users, monkeypatch):
    """Идущий прогон обновляет строку на каждом шаге — отбирать его нельзя."""
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    _make_stuck(session, users, seconds=60, status="running")
    assert watchdog.find_stuck(session, include_running=True) == []


# --------------------------------------------------------------------- захват
def test_claim_succeeds_once(session, users):
    item = _make_stuck(session, users, seconds=600)
    assert claim_item(session, item.id, stale_running_after_seconds=360) is True
    # Второй претендент уже опоздал: статус больше не queued.
    assert claim_item(session, item.id, stale_running_after_seconds=360) is False


def test_claim_takes_over_abandoned_running(session, users):
    item = _make_stuck(session, users, seconds=3600, status="running")
    assert claim_item(session, item.id, stale_running_after_seconds=360) is True


def test_claim_leaves_live_running_alone(session, users):
    item = _make_stuck(session, users, seconds=10, status="running")
    assert claim_item(session, item.id, stale_running_after_seconds=360) is False


def test_stale_running_seconds_follows_settings(monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 100)
    assert stale_running_seconds() == 300


# --------------------------------------------------------------------- проходы
def test_sweep_runs_pipeline_when_worker_is_dead(session, users, fake_redis, monkeypatch):
    """Главный сценарий: worker молчит, но пакет всё равно проверяется."""
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=600)

    result = watchdog.sweep()

    assert result["worker_alive"] is False
    assert result["mode"] == "inline"
    assert result["recovered"] == 1
    session.expire_all()
    assert session.get(RequestItem, item.id).status == "approved"


def test_sweep_requeues_when_worker_is_alive(session, users, fake_redis, monkeypatch):
    """Worker жив — значит, потерялось сообщение: задачу отправляем заново."""
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=600)
    worker_health.touch_heartbeat()

    sent: list[tuple[str, int]] = []
    from app.tasks import pipeline_tasks

    # Сторож обязан публиковать через `publish`: в фоновом потоке прокси
    # `shared_task` увёл бы задачу в очередь `celery` мимо worker'а.
    monkeypatch.setattr(
        pipeline_tasks,
        "publish",
        lambda name, *args: sent.append((name, *args)),
    )

    result = watchdog.sweep()

    assert result["worker_alive"] is True
    assert result["mode"] == "requeued"
    assert sent == [(pipeline_tasks.RUN_ITEM_PIPELINE, item.id)]
    session.expire_all()
    # Сторож сам конвейер не гонял — пакет ждёт worker'а.
    assert session.get(RequestItem, item.id).status == "queued"


def test_endless_requeue_is_escalated(session, users, fake_redis, monkeypatch, caplog):
    """Пакет, который не сдвигается после многих переотправок, должен стать заметен.

    Реальный случай заявки #9: сторож переотправлял пакет каждые 30 с, писал
    одну и ту же строку и этим маскировал ошибку задачи на worker'е.
    """
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=600)
    worker_health.touch_heartbeat()

    from app.tasks import pipeline_tasks

    # Задача уходит, но пакет не двигается — ровно то, что было в проде.
    monkeypatch.setattr(pipeline_tasks, "publish", lambda name, *args: None)
    watchdog._attempts.clear()

    for _ in range(watchdog.STALLED_AFTER_ATTEMPTS - 1):
        assert watchdog.sweep()["stalled"] == []

    with caplog.at_level("ERROR"):
        result = watchdog.sweep()

    assert result["stalled"] == [item.id]
    assert "не сдвигается" in caplog.text


def test_attempt_counter_resets_when_item_moves(session, users, fake_redis, monkeypatch):
    """Сдвинувшийся пакет не должен тянуть за собой счётчик прошлых попыток."""
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    item = _make_stuck(session, users, seconds=600)
    worker_health.touch_heartbeat()

    from app.tasks import pipeline_tasks

    monkeypatch.setattr(pipeline_tasks, "publish", lambda name, *args: None)
    watchdog._attempts.clear()

    watchdog.sweep()
    assert watchdog._attempts[item.id] == 1

    # Пакет забрали в работу — в следующий проход он уже не «зависший».
    item.status = "running"
    session.commit()
    watchdog.sweep()

    assert item.id not in watchdog._attempts


def test_sweep_is_quiet_when_nothing_is_stuck(session, users, fake_redis, monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    make_request(session, users["developer"])
    result = watchdog.sweep()
    assert result["stuck"] == 0
    assert result["recovered"] == 0


def test_sweep_survives_broken_item(session, users, fake_redis, monkeypatch):
    """Один сбойный пакет не должен останавливать разбор очереди."""
    monkeypatch.setattr(get_settings(), "pipeline_stuck_after_seconds", 120)
    first = _make_stuck(session, users, seconds=600)
    _, second = make_request(session, users["developer"], name="otherpkg")
    second.status = "queued"
    second.updated_at = utcnow() - timedelta(seconds=600)
    session.commit()

    from app.pipeline import runner

    real_run = runner.run_pipeline

    def flaky(session_, item, **kwargs):
        if item.id == first.id:
            raise RuntimeError("шаг упал (тест)")
        return real_run(session_, item, **kwargs)

    monkeypatch.setattr(runner, "run_pipeline", flaky)

    result = watchdog.sweep()

    assert result["recovered"] == 1  # второй пакет прошёл
    session.expire_all()
    assert session.get(RequestItem, second.id).status == "approved"


def test_watchdog_not_started_in_eager_mode(monkeypatch):
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", True)
    assert watchdog.start_watchdog() is None


def test_watchdog_not_started_when_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "pipeline_watchdog_enabled", False)
    monkeypatch.setattr(get_settings(), "celery_task_always_eager", False)
    assert watchdog.start_watchdog() is None
