"""Последовательный запуск конвейера и возобновление после ручных решений."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.adapters.notifier import EVENT_TITLES, Event, NotificationMessage, get_notifier
from app.core.errors import AppError, NotFoundError
from app.core.logging import get_logger
from app.core.metrics import pipeline_duration, pipeline_step_total
from app.db.base import utcnow
from app.db.enums import STEP_CODES, STEP_ORDER, STEP_TITLES
from app.db.models import ModerationRequest, PipelineStep, RequestItem, User
from app.pipeline.blockers import clear_blocker, pending_blockers  # noqa: F401
from app.pipeline.context import PipelineContext, StepOutcome
from app.pipeline.steps import STEP_HANDLERS
from app.services import audit

log = get_logger(__name__)

# Из какого шага возобновляется конвейер после снятия каждой из блокировок.
RESUME_FROM: dict[str, str] = {
    "quarantined": "license",  # карантин снят -> шаг 3
    "awaiting_legal": "download",  # лицензия подтверждена -> шаг 4
    "license_claimed": "download",
    "awaiting_security": "download",  # DevSecOps разрешил -> перекачиваем и публикуем
}


def _step_row(session: Session, item: RequestItem, code: str) -> PipelineStep:
    row = next((s for s in item.steps if s.step_code == code), None)
    if row is None:
        row = PipelineStep(
            request_item_id=item.id, step_code=code, step_order=STEP_ORDER[code], result="pending"
        )
        session.add(row)
        item.steps.append(row)
        session.flush()
    return row


def ensure_steps(session: Session, item: RequestItem) -> None:
    """Создаёт строки всех шагов, чтобы в UI было видно полный конвейер."""
    for code in STEP_CODES:
        _step_row(session, item, code)


def run_pipeline(
    session: Session,
    item: RequestItem,
    *,
    from_step: str = "db_check",
    actor: User | None = None,
    source: str = "task",
    resume_note: str | None = None,
) -> RequestItem:
    """Выполняет шаги начиная с `from_step`. Первый `fail`/останавливающий `warn` прекращает прогон."""
    version = item.package_version
    package = version.package
    request = item.request
    ctx = PipelineContext(
        session=session,
        item=item,
        version=version,
        package=package,
        request=request,
        actor=actor,
        source=source,
    )
    ensure_steps(session, item)
    start_index = STEP_ORDER.get(from_step, 0)

    item.status = "running"
    item.current_step = from_step
    item.blocked_reason = None
    item.waiting_since = None
    item.finished_at = None
    if version.status not in ("approved",):
        version.status = "checking"
    if resume_note:
        item.next_action = resume_note
    session.flush()

    stopped_by: StepOutcome | None = None
    stopped_code: str | None = None

    for handler in STEP_HANDLERS:
        order = STEP_ORDER[handler.code]
        if order < start_index:
            continue
        row = _step_row(session, item, handler.code)
        item.current_step = handler.code
        row.started_at = utcnow()
        row.result = "pending"
        session.flush()

        try:
            with pipeline_duration.labels(step=handler.code).time():
                outcome = handler.run(ctx)
        except AppError as exc:
            outcome = StepOutcome.fail(
                f"Шаг «{handler.title}» не выполнен: {exc.message}",
                details={"code": exc.code, **(exc.details or {})},
                item_status="failed",
                version_status="failed",
                next_action="Техническая ошибка проверки. Перезапустите заявку или обратитесь к admin.",
                notify_event=Event.PIPELINE_FAILED,
            )
        except Exception as exc:  # noqa: BLE001 - любая ошибка шага фиксируется в БД
            log.exception("шаг конвейера упал", extra={"step": handler.code, "item_id": item.id})
            outcome = StepOutcome.fail(
                f"Шаг «{handler.title}» не выполнен из-за внутренней ошибки: {exc}",
                item_status="failed",
                version_status="failed",
                next_action="Техническая ошибка проверки. Перезапустите заявку или обратитесь к admin.",
                notify_event=Event.PIPELINE_FAILED,
            )

        row.result = outcome.result
        row.message = outcome.message
        row.details = outcome.details
        row.finished_at = utcnow()
        pipeline_step_total.labels(
            step=handler.code, result=outcome.result, manager=package.manager
        ).inc()
        session.flush()

        if outcome.defer and not outcome.stop:
            # Шаг требует решения роли, но конвейер идёт дальше: вторая роль
            # должна увидеть пакет в своей очереди сразу, а не после первой.
            # Уведомление отправляется здесь — до финального исхода прогона.
            _notify(session, ctx, outcome)
            if outcome.version_status and version.status not in ("approved",):
                version.status = outcome.version_status
            session.flush()
            continue

        if outcome.stop or outcome.terminal:
            stopped_by, stopped_code = outcome, handler.code
            break

    if stopped_by is None:  # ни один шаг не выполнялся (from_step за пределами конвейера)
        stopped_by = StepOutcome(
            result="pass", message="Все шаги конвейера пройдены", terminal=True, item_status="approved"
        )
        stopped_code = STEP_CODES[-1]

    _finalize_item(session, ctx, stopped_by, stopped_code or STEP_CODES[-1])
    recompute_request_status(session, request)
    session.flush()
    return item


def _finalize_item(
    session: Session, ctx: PipelineContext, outcome: StepOutcome, stopped_code: str
) -> None:
    item, version = ctx.item, ctx.version

    # Шаги после остановки помечаются skipped с указанием, чем остановлено.
    stop_index = STEP_ORDER[stopped_code]
    skip_reason = (
        "Не выполнялся: пакет уже одобрен и опубликован."
        if outcome.terminal
        else f"Не выполнялся: конвейер остановлен на шаге «{STEP_TITLES[stopped_code]}»."
    )
    for code in STEP_CODES:
        if STEP_ORDER[code] <= stop_index:
            continue
        row = _step_row(session, item, code)
        if row.result in ("pending", "skipped"):
            row.result = "skipped"
            row.message = skip_reason
            row.finished_at = utcnow()

    item.status = outcome.item_status or ("approved" if outcome.terminal else "failed")
    item.current_step = stopped_code
    if outcome.next_action:
        item.next_action = outcome.next_action
    if outcome.result in ("warn", "fail") and not outcome.terminal:
        item.blocked_reason = outcome.message
        item.waiting_since = utcnow()
    if item.status in ("approved", "rejected", "blacklisted", "revoked", "failed"):
        item.finished_at = utcnow()
        item.waiting_since = None
    if outcome.version_status:
        version.status = outcome.version_status
    if outcome.result in ("warn", "fail"):
        version.status_reason = outcome.message
    session.flush()

    _notify(session, ctx, outcome)


def _notify(session: Session, ctx: PipelineContext, outcome: StepOutcome) -> None:
    if not outcome.notify_event and not outcome.notify_roles:
        return
    event = outcome.notify_event or Event.DECISION_MADE
    label = ctx.label
    message = NotificationMessage(
        event=event,
        title=f"{EVENT_TITLES.get(event, 'Событие')}: {label}",
        body=outcome.message,
        request_id=ctx.request.id,
        request_item_id=ctx.item.id,
        payload={"package": label, "manager": ctx.package.manager, "status": ctx.item.status},
    )
    notifier = get_notifier()
    if outcome.notify_roles:
        notifier.notify_roles(session, outcome.notify_roles, message)
    # Автор заявки уведомляется всегда: он ждёт результат.
    notifier.notify_users(session, [ctx.request.author_id], message)


def recompute_request_status(session: Session, request: ModerationRequest) -> str:
    """Агрегированный статус заявки по её пакетам."""
    statuses = [item.status for item in request.items]
    if not statuses:
        request.status = "pending"
        return request.status

    if any(s in ("queued", "running") for s in statuses):
        request.status = "pending"
    elif any(s == "awaiting_security" for s in statuses):
        request.status = "awaiting_security"
    elif any(s in ("awaiting_legal", "license_claimed") for s in statuses):
        request.status = "awaiting_legal"
    elif any(s == "quarantined" for s in statuses):
        request.status = "quarantined"
    elif all(s == "approved" for s in statuses):
        request.status = "approved"
    elif any(s == "approved" for s in statuses):
        request.status = "partially_approved"
    elif any(s == "failed" for s in statuses):
        request.status = "failed"
    else:
        request.status = "rejected"
    session.flush()
    return request.status


def resume_item(
    session: Session,
    item: RequestItem,
    *,
    actor: User | None = None,
    source: str = "task",
    from_step: str | None = None,
    note: str | None = None,
) -> RequestItem:
    """Возобновляет конвейер после ручного решения или снятия карантина."""
    step = from_step or RESUME_FROM.get(item.status, "db_check")
    audit.record(
        session,
        action="pipeline_resumed",
        entity_type="request_item",
        entity_id=item.id,
        actor=actor,
        old_value={"status": item.status},
        new_value={"from_step": step},
        source=source,
        comment=note,
    )
    return run_pipeline(session, item, from_step=step, actor=actor, source=source, resume_note=note)


def get_item(session: Session, item_id: int) -> RequestItem:
    item = session.get(RequestItem, item_id)
    if item is None:
        raise NotFoundError(f"Пакет заявки #{item_id} не найден")
    return item


def step_snapshot(item: RequestItem) -> list[dict[str, Any]]:
    """Шаги конвейера для карточки заявки: код, название, результат, объяснение, время."""
    rows = {s.step_code: s for s in item.steps}
    out: list[dict[str, Any]] = []
    for code in STEP_CODES:
        row = rows.get(code)
        out.append(
            {
                "code": code,
                "order": STEP_ORDER[code],
                "title": STEP_TITLES[code],
                "result": row.result if row else "pending",
                "message": row.message if row else None,
                "details": row.details if row else None,
                "started_at": row.started_at if row else None,
                "finished_at": row.finished_at if row else None,
            }
        )
    return out
