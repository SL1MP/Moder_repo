"""Сторож очереди: пакеты не должны ждать ручного запуска `moderctl run-pending`.

Задача уходит в Redis сразу после создания заявки. Если её никто не забрал
(worker упал, не поднялся, потерял сообщение), пакет молча остаётся в статусе
«в очереди» — снаружи это выглядит как «проверка идёт вечно».

Сторож живёт в процессе API (он точно работает, раз пользователь видит UI) и раз
в `PIPELINE_WATCHDOG_INTERVAL_SECONDS` смотрит, нет ли пакетов, висящих в очереди
дольше `PIPELINE_STUCK_AFTER_SECONDS`:

* worker жив — задача переотправляется в очередь (значит, потерялось сообщение);
* worker молчит — конвейер выполняется прямо здесь, синхронно.

В обоих случаях пакет захватывается через :func:`app.pipeline.claim.claim_item`,
поэтому двойного прогона не будет.
"""

from __future__ import annotations

import threading
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger, new_request_id, request_id_var
from app.core.metrics import pipeline_stuck_items, watchdog_recovered_total, worker_alive
from app.db.base import utcnow
from app.db.models import RequestItem
from app.db.session import session_scope
from app.pipeline.claim import STALE_RUNNING_FACTOR
from app.services.worker_health import worker_status

log = get_logger(__name__)

_thread: threading.Thread | None = None
_stop = threading.Event()

# Сколько проходов подряд пакет может числиться зависшим, прежде чем сторож
# признает, что переотправка не помогает, и скажет об этом громко.
STALLED_AFTER_ATTEMPTS = 3

# item_id → сколько проходов подряд пакет находится зависшим.
_attempts: dict[int, int] = {}


def find_stuck(session: Session, *, include_running: bool) -> list[int]:
    """Пакеты, которые давно ждут в очереди (и, если просят, брошенные `running`)."""
    s = get_settings()
    queued_before = utcnow() - timedelta(seconds=s.pipeline_stuck_after_seconds)
    ids = list(
        session.execute(
            select(RequestItem.id)
            .where(RequestItem.status == "queued", RequestItem.updated_at < queued_before)
            .order_by(RequestItem.id)
        ).scalars()
    )
    if include_running:
        running_before = utcnow() - timedelta(
            seconds=s.pipeline_stuck_after_seconds * STALE_RUNNING_FACTOR
        )
        ids += list(
            session.execute(
                select(RequestItem.id)
                .where(RequestItem.status == "running", RequestItem.updated_at < running_before)
                .order_by(RequestItem.id)
            ).scalars()
        )
    return ids


def sweep() -> dict[str, object]:
    """Один проход сторожа. Возвращает сводку — её же печатает CLI."""
    status = worker_status()
    worker_alive.set(1 if status.alive else 0)

    with session_scope() as session:
        stuck = find_stuck(session, include_running=not status.alive)
    pipeline_stuck_items.set(len(stuck))
    if not stuck:
        _attempts.clear()
        return {"worker_alive": status.alive, "stuck": 0, "recovered": 0, "mode": "idle"}

    mode = "requeued" if status.alive else "inline"
    log.warning(
        "сторож нашёл зависшие пакеты",
        extra={"stuck": len(stuck), "worker_alive": status.alive, "mode": mode},
    )
    stalled = _track_attempts(stuck)
    recovered = _requeue(stuck) if status.alive else _run_inline(stuck)
    watchdog_recovered_total.labels(mode=mode).inc(recovered)
    return {
        "worker_alive": status.alive,
        "worker_detail": status.detail,
        "stuck": len(stuck),
        "recovered": recovered,
        "mode": mode,
        "stalled": stalled,
    }


def _track_attempts(stuck: list[int]) -> list[int]:
    """Ловит бесконечный цикл: один и тот же пакет переотправляется без результата.

    Страховка обязана быть заметной, когда перестаёт помогать. Иначе сторож
    молча переотправляет пакет каждые 30 секунд, снаружи всё выглядит живым, а
    настоящая ошибка — внутри задачи на worker'е — не видна никому.
    """
    for item_id in list(_attempts):
        if item_id not in stuck:
            del _attempts[item_id]  # пакет сдвинулся, счётчик больше не нужен

    stalled: list[int] = []
    for item_id in stuck:
        _attempts[item_id] = _attempts.get(item_id, 0) + 1
        if _attempts[item_id] >= STALLED_AFTER_ATTEMPTS:
            stalled.append(item_id)

    if stalled:
        log.error(
            "пакет не сдвигается после многократной переотправки — "
            "ищите ошибку задачи в логах worker'а",
            extra={"item_ids": stalled, "attempts": STALLED_AFTER_ATTEMPTS},
        )
    return stalled


def _requeue(item_ids: list[int]) -> int:
    """Worker жив — значит, потерялось сообщение: отправляем задачу заново.

    Публикуем через `publish`, а не через прокси `shared_task`: сторож работает
    в фоновом потоке, где «текущее приложение» Celery проваливается на
    приложение по умолчанию, и задача ушла бы в очередь `celery` мимо worker'а.
    """
    from app.tasks.pipeline_tasks import RUN_ITEM_PIPELINE, publish

    sent = 0
    for item_id in item_ids:
        try:
            publish(RUN_ITEM_PIPELINE, item_id)
            sent += 1
        except Exception as exc:  # noqa: BLE001 - брокер мог отвалиться между проверками
            log.warning("не удалось переотправить задачу: %s", exc, extra={"item_id": item_id})
    return sent


def _run_inline(item_ids: list[int]) -> int:
    """Worker молчит — выполняем конвейер здесь же, как это делает `run-pending`."""
    from app.pipeline.claim import claim_item, stale_running_seconds
    from app.pipeline.runner import run_pipeline

    stale_after = stale_running_seconds()
    done = 0
    for item_id in item_ids:
        request_id_var.set(new_request_id())
        try:
            with session_scope() as session:
                if not claim_item(session, item_id, stale_running_after_seconds=stale_after):
                    continue  # пакет успел подхватить кто-то ещё
                item = session.get(RequestItem, item_id)
                if item is None:
                    continue
                run_pipeline(session, item, source="watchdog")
                done += 1
        except Exception:  # noqa: BLE001 - один сбойный пакет не должен останавливать сторожа
            log.exception("сторож не смог прогнать пакет", extra={"item_id": item_id})
    return done


def _loop() -> None:  # pragma: no cover - тело фонового потока
    interval = max(5, get_settings().pipeline_watchdog_interval_seconds)
    while not _stop.is_set():
        # Первый проход тоже с задержкой: даём worker'у шанс забрать задачу штатно.
        _stop.wait(interval)
        if _stop.is_set():
            break
        try:
            sweep()
        except Exception:  # noqa: BLE001 - сторож не имеет права умереть
            log.exception("проход сторожа завершился ошибкой")


def start_watchdog() -> threading.Thread | None:
    """Запускает сторожа в процессе API. None — если он выключен настройкой."""
    global _thread
    s = get_settings()
    if not s.pipeline_watchdog_enabled:
        log.info("сторож очереди выключен (PIPELINE_WATCHDOG_ENABLED=false)")
        return None
    if s.celery_task_always_eager:
        # Задачи и так выполняются синхронно в API — сторожить нечего.
        # Логируем и этот случай: молчаливый выход неотличим в логах от
        # «сторож вообще не вызывался», а различать их нужно.
        log.info("сторож очереди не нужен: задачи выполняются синхронно (eager-режим)")
        return None
    if _thread is not None and _thread.is_alive():
        return _thread
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="pipeline-watchdog", daemon=True)
    _thread.start()
    log.info(
        "сторож очереди запущен",
        extra={
            "interval": s.pipeline_watchdog_interval_seconds,
            "stuck_after": s.pipeline_stuck_after_seconds,
        },
    )
    return _thread


def stop_watchdog() -> None:
    _stop.set()
