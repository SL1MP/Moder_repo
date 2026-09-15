"""Задачи конвейера: запуск, возобновление, перепроверка, отзыв."""

from __future__ import annotations

from celery import shared_task

from app.core.logging import get_logger, new_request_id, request_id_var
from app.db.models import ModerationRequest, RequestItem
from app.db.session import session_scope
from app.pipeline.claim import claim_item, stale_running_seconds
from app.pipeline.runner import recompute_request_status, resume_item, run_pipeline

# Импорт делает наше приложение Celery текущим — иначе shared_task привяжется к
# приложению по умолчанию и настройка task_always_eager не применится.
from app.tasks.celery_app import celery_app, publish  # noqa: F401,E402

log = get_logger(__name__)

RUN_REQUEST_PIPELINE = "app.tasks.pipeline_tasks.run_request_pipeline"
RUN_ITEM_PIPELINE = "app.tasks.pipeline_tasks.run_item_pipeline"
RESUME_ITEM_PIPELINE = "app.tasks.pipeline_tasks.resume_item_pipeline"


@shared_task(bind=True, name="app.tasks.pipeline_tasks.run_request_pipeline", max_retries=5)
def run_request_pipeline(self, request_id: int) -> dict[str, str]:
    """Прогоняет конвейер по всем пакетам заявки."""
    request_id_var.set(new_request_id())
    results: dict[str, str] = {}
    with session_scope() as session:
        request = session.get(ModerationRequest, request_id)
        if request is None:
            log.warning("заявка не найдена", extra={"request_id": request_id})
            return {}
        item_ids = [item.id for item in request.items if item.status in ("queued", "running")]
    for item_id in item_ids:
        results[str(item_id)] = run_item_pipeline(item_id)["status"]
    with session_scope() as session:
        request = session.get(ModerationRequest, request_id)
        if request is not None:
            recompute_request_status(session, request)
    return results


@shared_task(bind=True, name="app.tasks.pipeline_tasks.run_item_pipeline", max_retries=5)
def run_item_pipeline(self, item_id: int, from_step: str = "db_check") -> dict[str, str]:
    """Прогоняет конвейер по одному пакету заявки.

    Пакет захватывается атомарно: ту же задачу может переотправить сторож
    очереди (см. app/services/watchdog.py), и прогонять конвейер дважды нельзя.
    """
    request_id_var.set(new_request_id())
    stale_after = stale_running_seconds()
    with session_scope() as session:
        item = session.get(RequestItem, item_id)
        if item is None:
            log.warning("пакет заявки не найден", extra={"item_id": item_id})
            return {"status": "not_found"}
        if not claim_item(session, item_id, stale_running_after_seconds=stale_after):
            log.info("пакет уже обрабатывается, пропускаем", extra={"item_id": item_id})
            return {"status": "skipped", "step": item.current_step or ""}
        run_pipeline(session, item, from_step=from_step, source="task")
        return {"status": item.status, "step": item.current_step or ""}


@shared_task(bind=True, name="app.tasks.pipeline_tasks.resume_item_pipeline", max_retries=5)
def resume_item_pipeline(self, item_id: int, from_step: str | None = None, note: str | None = None):
    """Возобновляет конвейер после ручного решения или снятия карантина."""
    request_id_var.set(new_request_id())
    with session_scope() as session:
        item = session.get(RequestItem, item_id)
        if item is None:
            return {"status": "not_found"}
        resume_item(session, item, from_step=from_step, source="task", note=note)
        return {"status": item.status, "step": item.current_step or ""}


def enqueue_request_pipeline(request_id: int) -> None:
    """Асинхронный запуск конвейера после создания заявки.

    Если брокер недоступен (локальный прогон, отладка), задача выполняется синхронно —
    заявка не должна «зависнуть» из-за недоступного Redis.
    """
    try:
        publish(RUN_REQUEST_PIPELINE, request_id)
    except Exception as exc:  # noqa: BLE001 - падение брокера не должно ломать API
        log.warning("брокер недоступен, конвейер выполняется синхронно: %s", exc)
        run_request_pipeline(request_id)


def enqueue_resume(item_id: int, from_step: str | None = None, note: str | None = None) -> None:
    try:
        publish(RESUME_ITEM_PIPELINE, item_id, from_step, note)
    except Exception as exc:  # noqa: BLE001
        log.warning("брокер недоступен, возобновление выполняется синхронно: %s", exc)
        resume_item_pipeline(item_id, from_step, note)
