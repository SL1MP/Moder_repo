"""GitLab: подключение из профиля и заведение заявки по файлу из приватного проекта."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, rate_limited, require_any_role
from app.core.config import get_settings
from app.core.errors import ValidationError
from app.db.models import User
from app.db.session import get_db
from app.managers.registry import detect_manager_by_file
from app.schemas import CreateRequestOut, GitlabFileIn
from app.services import audit, requests_service
from app.services import gitlab as gitlab_service
from app.tasks.pipeline_tasks import enqueue_request_pipeline

router = APIRouter(prefix="/gitlab", tags=["GitLab"])


@router.get("/status", summary="Состояние подключения GitLab")
def gitlab_status(user: User = Depends(get_current_user)) -> dict[str, object]:
    s = get_settings()
    return {
        "enabled": bool(s.gitlab_url and s.gitlab_oauth_client_id),
        "gitlab_url": s.gitlab_url,
        "connected": bool(user.gitlab_access_token_enc),
        "gitlab_username": user.gitlab_username,
        "expires_at": user.gitlab_token_expires_at,
        "scopes": gitlab_service.SCOPES,
    }


@router.get("/authorize", summary="Ссылка для подключения GitLab (OAuth)")
def authorize(_user: User = Depends(get_current_user)) -> dict[str, str]:
    url, state = gitlab_service.authorize_url()
    return {"authorize_url": url, "state": state}


@router.get("/callback", summary="Callback OAuth GitLab")
def callback(
    request: Request,
    code: str = Query(min_length=8),
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    gitlab_service.exchange_code(session, user, code)
    audit.record(
        session,
        action="gitlab_connected",
        entity_type="user",
        entity_id=user.id,
        actor=user,
        new_value={"gitlab_username": user.gitlab_username},
        source="ui",
        ip=client_ip(request),
    )
    session.commit()
    return {"connected": True, "gitlab_username": user.gitlab_username}


@router.delete("/connection", summary="Отключить GitLab")
def disconnect(
    request: Request,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, bool]:
    gitlab_service.disconnect(session, user)
    audit.record(
        session,
        action="gitlab_disconnected",
        entity_type="user",
        entity_id=user.id,
        actor=user,
        source="ui",
        ip=client_ip(request),
    )
    session.commit()
    return {"connected": False}


@router.post(
    "/requests",
    response_model=CreateRequestOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Заявка по файлу зависимостей из GitLab",
)
def create_from_gitlab(
    request: Request,
    payload: GitlabFileIn,
    response: Response,
    session: Session = Depends(get_db),
    user: User = Depends(rate_limited),
    _role: User = Depends(require_any_role),
) -> CreateRequestOut:
    file = gitlab_service.read_file(
        session, user, project=payload.project, path=payload.path, ref=payload.ref
    )
    manager = payload.manager or detect_manager_by_file(payload.path)
    if not manager:
        raise ValidationError(
            f"Не удалось определить пакетный менеджер по имени файла «{payload.path}» — "
            "укажите поле manager"
        )

    parse = requests_service.parse_payload(
        session,
        manager=manager,
        filename=payload.path,
        content=file.content,
        include_transitive=payload.include_transitive,
    )
    origin = f"gitlab:{payload.project}:{payload.ref}:{payload.path}"
    req = requests_service.create_request(
        session,
        author=user,
        parse_result=parse,
        reason=payload.reason,
        source="gitlab",
        origin_file=origin,
        include_transitive=payload.include_transitive,
        actor_role=getattr(request.state, "actor_role", None),
    )
    out = CreateRequestOut(
        request_id=req.id,
        manager=req.manager,
        status=req.status,
        accepted=len(parse.new),
        skipped_already_in_base=sum(1 for p in parse.packages if p.state == "already_in_base"),
        invalid=sum(1 for p in parse.packages if p.state == "invalid_format"),
        warnings=[*parse.warnings, f"Файл прочитан из GitLab: {origin} (commit {file.commit_id})"],
        packages=[p.to_dict() for p in parse.packages],
        status_url=f"/api/v1/requests/{req.id}",
    )
    session.commit()
    if parse.new:
        enqueue_request_pipeline(req.id)
    return out
