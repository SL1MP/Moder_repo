"""Аудит-лог: кто, что, когда, старое/новое значение, источник."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import request_id_var
from app.db.base import utcnow
from app.db.models import AuditLog, User

SOURCE_UI = "ui"
SOURCE_API = "api"
SOURCE_TASK = "task"
SOURCE_CLI = "cli"

SOURCE_TITLES = {
    SOURCE_UI: "UI",
    SOURCE_API: "REST API",
    SOURCE_TASK: "фоновая задача",
    SOURCE_CLI: "CLI",
}


def record(
    session: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str | int | None = None,
    actor: User | None = None,
    actor_name: str | None = None,
    actor_role: str | None = None,
    old_value: Any = None,
    new_value: Any = None,
    source: str = SOURCE_API,
    comment: str | None = None,
    ip: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_name=actor_name or (actor.username if actor else "system"),
        actor_role=actor_role or (_primary_role(actor) if actor else None),
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        old_value=old_value,
        new_value=new_value,
        source=source,
        request_id=request_id_var.get(),
        ip=ip,
        comment=comment,
        created_at=utcnow(),
    )
    session.add(entry)
    session.flush()
    return entry


def _primary_role(user: User) -> str | None:
    for role in ("admin", "devsecops", "legal", "developer"):
        if user.has_role(role):
            return role
    return None
