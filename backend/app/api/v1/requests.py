"""REST API добавления пакетов — первый рабочий инструмент (раздел 6 задания).

Один эндпоинт `POST /api/v1/requests` обслуживает оба способа заведения:
`application/json` со списком пакетов и `multipart/form-data` с файлом зависимостей.
Тип входа определяется по `Content-Type`, дальше обработка общая.
"""

from __future__ import annotations

import json
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, rate_limited, require_any_role
from app.core.errors import ForbiddenError, ValidationError
from app.core.logging import get_logger
from app.db.enums import STATUS_TITLES
from app.db.models import ModerationRequest, User
from app.db.session import get_db
from app.schemas import CreateRequestOut, RequestListItem, RequestOut
from app.services import audit, requests_service
from app.tasks.pipeline_tasks import enqueue_request_pipeline

log = get_logger(__name__)
router = APIRouter(prefix="/requests", tags=["Заявки"])

_TRUE = {"true", "1", "yes", "on"}


def _normalize_packages(items: list[Any]) -> tuple[list[str], list[dict[str, str]]]:
    """Разделяет краткую строковую форму (`requests==2.31.0`) и объектную."""
    entries: list[str] = []
    structured: list[dict[str, str]] = []
    for item in items:
        if isinstance(item, str):
            if item.strip():
                entries.append(item.strip())
        elif isinstance(item, dict):
            structured.append(
                {"name": str(item.get("name", "")), "version": str(item.get("version", ""))}
            )
        else:
            raise ValidationError(
                "Элемент packages должен быть строкой или объектом {name, version}",
                got=str(type(item).__name__),
            )
    return entries, structured


@router.post(
    "",
    response_model=CreateRequestOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Создать заявку: перечисление пакетов или файл с зависимостями",
)
async def create_request(
    request: Request,
    response: Response,
    session: Session = Depends(get_db),
    user: User = Depends(rate_limited),
    _role: User = Depends(require_any_role),
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> CreateRequestOut:
    content_type = (request.headers.get("content-type") or "").lower()
    manager: str | None
    reason: str | None
    include_transitive = False
    filename: str | None = None
    content: bytes | None = None
    entries: list[str] = []
    structured: list[dict[str, str]] = []

    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        manager = str(form.get("manager") or "").strip().lower() or None
        reason = str(form.get("reason")) if form.get("reason") is not None else None
        raw_flag = form.get("include_transitive")
        include_transitive = str(raw_flag).lower() in _TRUE if raw_flag is not None else False
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise ValidationError("В multipart-запросе нет файла в поле file")
        if not manager:
            raise ValidationError("Для загрузки файла нужно указать поле manager")
        filename = upload.filename or ""
        content = await upload.read()
    else:
        raw = await request.body()
        if not raw:
            raise ValidationError(
                "Передайте JSON {manager, packages[]} либо multipart с полями manager и file"
            )
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Тело запроса не является корректным JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise ValidationError("Тело запроса должно быть JSON-объектом")
        manager = str(body.get("manager") or "").strip().lower() or None
        reason = body.get("reason")
        if not manager:
            raise ValidationError("Не указан пакетный менеджер (поле manager)")
        packages = body.get("packages")
        if not isinstance(packages, list) or not packages:
            raise ValidationError("Список packages пуст или имеет неверный тип")
        entries, structured = _normalize_packages(packages)

    source = "ui" if request.headers.get("x-client") == "web" else "api"
    actor_role = getattr(request.state, "actor_role", None)

    def work() -> tuple[CreateRequestOut, bool, int]:
        if idempotency_key:
            existing = requests_service.find_by_idempotency_key(session, idempotency_key)
            if existing is not None:
                return _idempotent_response(session, existing), False, existing.id

        parse = requests_service.parse_payload(
            session,
            manager=manager or "",
            entries=entries,
            structured=structured,
            filename=filename,
            content=content,
            include_transitive=include_transitive,
        )
        req = requests_service.create_request(
            session,
            author=user,
            parse_result=parse,
            reason=reason,
            source=source,
            idempotency_key=idempotency_key,
            origin_file=filename,
            include_transitive=include_transitive,
            actor_role=actor_role,
        )
        out = CreateRequestOut(
            request_id=req.id,
            manager=req.manager,
            status=req.status,
            accepted=len(parse.new),
            skipped_already_in_base=sum(1 for p in parse.packages if p.state == "already_in_base"),
            invalid=sum(1 for p in parse.packages if p.state == "invalid_format"),
            warnings=parse.warnings,
            packages=[p.to_dict() for p in parse.packages],
            status_url=f"/api/v1/requests/{req.id}",
        )
        session.commit()
        return out, bool(parse.new), req.id

    result, should_run, request_id = await run_in_threadpool(work)
    if not should_run and idempotency_key:
        response.status_code = status.HTTP_200_OK
    if should_run:
        await run_in_threadpool(enqueue_request_pipeline, request_id)
    return result


def _idempotent_response(session: Session, existing: ModerationRequest) -> CreateRequestOut:
    """Повтор с тем же Idempotency-Key возвращает ту же заявку."""
    payload = requests_service.request_payload(session, existing, include_steps=False)
    return CreateRequestOut(
        request_id=existing.id,
        manager=existing.manager,
        status=existing.status,
        accepted=len(existing.items),
        skipped_already_in_base=0,
        invalid=0,
        warnings=existing.warnings or [],
        packages=[
            {
                "raw": f"{i['name']} {i['version']}",
                "state": "new",
                "name": i["name"],
                "version": i["version"],
                "dependency_kind": i["dependency_kind"],
                "status": i["status"],
                "message": "Заявка уже создана ранее с этим Idempotency-Key",
            }
            for i in payload["packages"]
        ],
        status_url=f"/api/v1/requests/{existing.id}",
    )


@router.get("", response_model=list[RequestListItem], summary="Список заявок")
def list_requests(
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    mine: bool = Query(default=False, description="Только свои заявки"),
    request_status: str | None = Query(default=None, alias="status"),
    manager: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
) -> list[RequestListItem]:
    stmt = select(ModerationRequest)
    # developer видит свои заявки; devsecops / legal / admin — все.
    if mine or not user.has_role("admin", "devsecops", "legal"):
        stmt = stmt.where(ModerationRequest.author_id == user.id)
    if request_status:
        stmt = stmt.where(ModerationRequest.status == request_status)
    if manager:
        stmt = stmt.where(ModerationRequest.manager == manager)
    stmt = stmt.order_by(ModerationRequest.id.desc()).limit(limit).offset(offset)

    return [
        RequestListItem(
            request_id=req.id,
            manager=req.manager,
            status=req.status,
            status_title=STATUS_TITLES.get(req.status, req.status),
            author=req.author.username if req.author else None,
            reason=req.reason,
            created_at=req.created_at,
            total=len(req.items),
            approved=sum(1 for i in req.items if i.status == "approved"),
        )
        for req in session.execute(stmt).scalars()
    ]


@router.get("/{request_id}", response_model=RequestOut, summary="Статус заявки")
def get_request(
    request_id: int,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    wait: bool = Query(default=False, description="Блокирующий вариант для CI"),
    timeout: int = Query(default=300, ge=1, le=1800),
) -> RequestOut:
    req = requests_service.get_request(session, request_id)
    _check_access(user, req)

    if wait:
        # Блокирующий вариант для CI: ждём финального статуса, но не дольше timeout.
        deadline = time.monotonic() + timeout
        while not requests_service.is_settled(req) and time.monotonic() < deadline:
            time.sleep(1.0)
            session.expire_all()
            req = requests_service.get_request(session, request_id)
    return RequestOut(**requests_service.request_payload(session, req))


@router.post("/{request_id}/retry", response_model=RequestOut, summary="Перезапустить проверку")
def retry_request(
    request: Request,
    request_id: int,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> RequestOut:
    req = requests_service.get_request(session, request_id)
    _check_access(user, req)
    if not (user.has_role("admin", "devsecops") or req.author_id == user.id):
        raise ForbiddenError("Перезапустить заявку может её автор, DevSecOps или администратор")

    restarted = 0
    for item in req.items:
        if item.status == "failed":
            item.status = "queued"
            item.blocked_reason = None
            item.finished_at = None
            restarted += 1
    audit.record(
        session,
        action="request_retried",
        entity_type="moderation_request",
        entity_id=req.id,
        actor=user,
        new_value={"restarted_items": restarted},
        source="api",
        ip=client_ip(request),
    )
    session.commit()
    if restarted:
        enqueue_request_pipeline(req.id)
        session.expire_all()
        req = requests_service.get_request(session, request_id)
    return RequestOut(**requests_service.request_payload(session, req))


def _check_access(user: User, req: ModerationRequest) -> None:
    if user.has_role("admin", "devsecops", "legal") or req.author_id == user.id:
        return
    raise ForbiddenError("Заявка доступна её автору, DevSecOps, юристам и администратору")
