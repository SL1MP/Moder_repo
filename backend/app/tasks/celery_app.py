"""Celery: конвейер проверок, скачивание, публикация; beat — регламентные задачи."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready, worker_shutdown

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.services.worker_health import start_heartbeat_thread, stop_heartbeat_thread

settings = get_settings()

celery_app = Celery(
    "moderation",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.tasks.pipeline_tasks", "app.tasks.scheduled"],
)

celery_app.conf.update(
    task_acks_late=True,  # задача подтверждается после выполнения — переживает рестарт
    task_reject_on_worker_lost=True,
    task_track_started=True,
    task_time_limit=1800,
    task_soft_time_limit=1500,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=200,
    result_expires=86400,
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=settings.celery_task_always_eager,
    task_default_queue="moderation",
    task_routes={
        "app.tasks.pipeline_tasks.*": {"queue": "moderation"},
        "app.tasks.scheduled.*": {"queue": "maintenance"},
    },
    # Dead-letter: исчерпавшие ретраи задачи уходят в отдельную очередь для разбора.
    task_annotations={
        "*": {
            "max_retries": 5,
            "retry_backoff": True,
            "retry_backoff_max": 600,
            "retry_jitter": True,
        }
    },
    timezone="UTC",
    enable_utc=True,
)


def publish(task_name: str, *args) -> object:
    """Ставит задачу строго через это приложение Celery, а не через `current_app`.

    Прокси, который возвращает `shared_task`, резолвится по `current_app`, а
    «текущее приложение» в Celery — thread-local. В фоновом потоке (сторож
    очереди) и в пуле потоков FastAPI (синхронные эндпоинты, `run_in_threadpool`)
    оно проваливается на приложение по умолчанию: у того нет ни наших
    `task_routes`, ни очереди `moderation`, а `task_default_queue` равен
    `celery`. Публикация при этом проходит без ошибки, но задача уходит в
    очередь, которую не слушает ни один worker, — пакет навсегда остаётся
    «в очереди».

    Обращение к задаче через реестр приложения снимает зависимость от потока и
    сохраняет `task_always_eager`.
    """
    return celery_app.tasks[task_name].apply_async(args=list(args))


def _osv_schedule() -> crontab:
    parts = (settings.osv_sync_cron or "0 4 * * *").split()
    if len(parts) != 5:
        return crontab(minute=0, hour=4)
    minute, hour, dom, month, dow = parts
    return crontab(minute=minute, hour=hour, day_of_month=dom, month_of_year=month, day_of_week=dow)


celery_app.conf.beat_schedule = {
    "release-quarantine": {
        "task": "app.tasks.scheduled.release_quarantine",
        "schedule": crontab(minute="*/15"),
    },
    "sync-osv-snapshot": {
        "task": "app.tasks.scheduled.sync_osv_snapshot",
        "schedule": _osv_schedule(),
    },
    "cleanup-orphan-objects": {
        "task": "app.tasks.scheduled.cleanup_orphan_objects",
        "schedule": crontab(minute=30, hour="*/2"),
    },
}


@celery_app.on_after_configure.connect
def _setup_logging(sender, **_kwargs):  # pragma: no cover - хук Celery
    configure_logging(settings.log_level)


@worker_ready.connect
def _start_heartbeat(**_kwargs):  # pragma: no cover - хук Celery
    """Пока worker жив, он отмечается в Redis — API видит это на экране «Настройка»."""
    start_heartbeat_thread()


@worker_shutdown.connect
def _stop_heartbeat(**_kwargs):  # pragma: no cover - хук Celery
    stop_heartbeat_thread()
