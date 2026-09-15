"""Уведомления внутри сервиса: непрочитанные события и счётчики очередей."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import utcnow
from app.db.models import Notification, RequestItem, User
from app.db.session import get_db
from app.schemas import MarkReadIn, NotificationOut, NotificationsOut

router = APIRouter(tags=["Уведомления"])


@router.get("/notifications", response_model=NotificationsOut, summary="Мои уведомления")
def list_notifications(
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    only_unread: bool = Query(default=False),
    limit: int = Query(default=50, le=200),
) -> NotificationsOut:
    stmt = select(Notification).where(Notification.user_id == user.id)
    if only_unread:
        stmt = stmt.where(Notification.read_at.is_(None))
    stmt = stmt.order_by(Notification.id.desc()).limit(limit)
    items = list(session.execute(stmt).scalars())
    unread = int(
        session.execute(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user.id, Notification.read_at.is_(None))
        ).scalar_one()
    )
    return NotificationsOut(
        unread=unread, items=[NotificationOut.model_validate(i) for i in items]
    )


@router.post("/notifications/read", summary="Отметить прочитанными")
def mark_read(
    payload: MarkReadIn,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, int]:
    stmt = select(Notification).where(
        Notification.user_id == user.id, Notification.read_at.is_(None)
    )
    if not payload.all:
        stmt = stmt.where(Notification.id.in_(payload.ids or []))
    updated = 0
    for row in session.execute(stmt).scalars():
        row.read_at = utcnow()
        updated += 1
    session.commit()
    return {"updated": updated}


@router.get("/queue/counters", summary="Счётчики очередей ролей")
def queue_counters(
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, int]:
    def count(statuses: list[str]) -> int:
        return int(
            session.execute(
                select(func.count()).select_from(RequestItem).where(RequestItem.status.in_(statuses))
            ).scalar_one()
        )

    counters = {
        "unread_notifications": int(
            session.execute(
                select(func.count())
                .select_from(Notification)
                .where(Notification.user_id == user.id, Notification.read_at.is_(None))
            ).scalar_one()
        )
    }
    if user.has_role("admin", "devsecops"):
        counters["security"] = count(["awaiting_security"])
        counters["quarantined"] = count(["quarantined"])
    if user.has_role("admin", "legal"):
        counters["legal"] = count(["awaiting_legal", "license_claimed"])
    return counters
