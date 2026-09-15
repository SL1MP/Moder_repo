"""Публикация задач не должна зависеть от того, из какого потока её позвали.

Тот самый дефект, из-за которого пакеты молча оставались «в очереди».
«Текущее приложение» в Celery — thread-local, а прокси `shared_task`
резолвится именно по нему. В фоновом потоке (сторож очереди) и в пуле потоков
FastAPI (синхронные эндпоинты, `run_in_threadpool`) прокси проваливался на
приложение по умолчанию: очередь `celery` вместо `moderation`, без
`task_routes`. Публикация проходила без ошибки, worker такую очередь не
слушает — и пакет висел вечно.
"""

from __future__ import annotations

import threading

import pytest
from celery import current_app

from app.tasks.celery_app import celery_app, publish
from app.tasks.pipeline_tasks import (
    RESUME_ITEM_PIPELINE,
    RUN_ITEM_PIPELINE,
    RUN_REQUEST_PIPELINE,
)
from app.tasks.scheduled import RESCAN_APPROVED, SYNC_OSV_SNAPSHOT

ALL_TASK_NAMES = [
    RUN_REQUEST_PIPELINE,
    RUN_ITEM_PIPELINE,
    RESUME_ITEM_PIPELINE,
    SYNC_OSV_SNAPSHOT,
    RESCAN_APPROVED,
]


def _in_thread(fn):
    """Выполняет функцию в отдельном потоке и возвращает её результат."""
    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - пробрасываем в основной поток
            box["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]


def test_current_app_really_falls_back_in_a_thread():
    """Фиксируем само поведение Celery, ради которого написан `publish`."""
    in_thread = _in_thread(lambda: current_app._get_current_object().main)

    assert current_app._get_current_object().main == "moderation"
    assert in_thread != "moderation"  # приложение по умолчанию, не наше


@pytest.mark.parametrize("task_name", ALL_TASK_NAMES)
def test_publish_uses_our_app_from_any_thread(task_name):
    """`publish` берёт задачу из нашего реестра независимо от потока."""
    from_main = celery_app.tasks[task_name]
    from_thread = _in_thread(lambda: celery_app.tasks[task_name])

    assert from_thread is from_main
    assert from_thread.app is celery_app


@pytest.mark.parametrize("task_name", ALL_TASK_NAMES)
def test_every_task_routes_to_a_real_queue(task_name):
    """Ни одна задача не должна уезжать в очередь `celery` — её никто не слушает."""
    route = celery_app.amqp.router.route({}, task_name)
    queue = route.get("queue")
    name = getattr(queue, "name", queue) or celery_app.conf.task_default_queue

    assert str(name) in ("moderation", "maintenance")


def test_publish_routes_correctly_from_a_thread(monkeypatch):
    """Ключевая проверка: из потока задача уходит в moderation, а не в celery."""
    sent: list[tuple[str, dict]] = []

    def fake_apply_async(self, args=None, **kwargs):
        route = celery_app.amqp.router.route({}, self.name)
        queue = route.get("queue")
        sent.append((self.name, {"queue": str(getattr(queue, "name", queue))}))
        return None

    monkeypatch.setattr(
        celery_app.tasks[RUN_ITEM_PIPELINE].__class__, "apply_async", fake_apply_async
    )

    _in_thread(lambda: publish(RUN_ITEM_PIPELINE, 9))

    assert sent == [(RUN_ITEM_PIPELINE, {"queue": "moderation"})]


def test_publish_passes_arguments_through(monkeypatch):
    captured: dict[str, object] = {}

    def fake_apply_async(self, args=None, **kwargs):
        captured["name"] = self.name
        captured["args"] = args
        return "task-id"

    monkeypatch.setattr(
        celery_app.tasks[RESUME_ITEM_PIPELINE].__class__, "apply_async", fake_apply_async
    )

    result = publish(RESUME_ITEM_PIPELINE, 42, "license", "заметка")

    assert captured["args"] == [42, "license", "заметка"]
    assert result == "task-id"
