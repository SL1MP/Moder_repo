"""Обсуждения: ветка на заявку и на каждый её пакет."""

from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.notifier import EVENT_TITLES, Event, NotificationMessage, get_notifier
from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.errors import ForbiddenError, NotFoundError, ValidationError
from app.core.security import primary_role
from app.db.base import utcnow
from app.db.models import Comment, ModerationRequest, RequestItem, User
from app.db.session import get_db
from app.schemas import CommentIn, CommentOut, CommentUpdateIn
from app.services import audit, requests_service

router = APIRouter(tags=["Обсуждения"])

MENTION_RE = re.compile(r"(?<![\w/])@([A-Za-z0-9._\-]{2,64})")


def _check_participant(session: Session, user: User, request: ModerationRequest) -> None:
    """Обсуждение видно всем участникам заявки: автору, DevSecOps, юристам, admin."""
    if user.has_role("admin", "devsecops", "legal") or request.author_id == user.id:
        return
    raise ForbiddenError("Обсуждение доступно участникам заявки")


def _payload(comment: Comment, user: User) -> CommentOut:
    s = get_settings()
    editable_until = comment.created_at + timedelta(minutes=s.comment_edit_window_minutes)
    created = comment.created_at
    now = utcnow()
    if created.tzinfo is None:
        editable_until = editable_until.replace(tzinfo=now.tzinfo)
    return CommentOut(
        id=comment.id,
        request_id=comment.request_id,
        request_item_id=comment.request_item_id,
        author=comment.author.username if comment.author else "—",
        author_role=comment.author_role,
        body="Сообщение удалено" if comment.deleted_at else comment.body,
        mentions=comment.mentions or [],
        is_edited=comment.is_edited,
        edited_at=comment.edited_at,
        deleted=comment.deleted_at is not None,
        created_at=comment.created_at,
        can_edit=(
            comment.deleted_at is None
            and (comment.author_id == user.id or user.has_role("admin"))
        ),
    )


@router.get(
    "/requests/{request_id}/comments",
    response_model=list[CommentOut],
    summary="Обсуждение заявки",
)
def list_comments(
    request_id: int,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    request_item_id: int | None = Query(default=None, description="Только ветка одного пакета"),
) -> list[CommentOut]:
    request = requests_service.get_request(session, request_id)
    _check_participant(session, user, request)
    stmt = select(Comment).where(Comment.request_id == request_id)
    if request_item_id is not None:
        stmt = stmt.where(Comment.request_item_id == request_item_id)
    stmt = stmt.order_by(Comment.id.asc())
    return [_payload(c, user) for c in session.execute(stmt).scalars()]


@router.post(
    "/requests/{request_id}/comments", response_model=CommentOut, summary="Добавить сообщение"
)
def add_comment(
    request_id: int,
    payload: CommentIn,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CommentOut:
    request = requests_service.get_request(session, request_id)
    _check_participant(session, user, request)

    if payload.request_item_id is not None:
        item = session.get(RequestItem, payload.request_item_id)
        if item is None or item.request_id != request_id:
            raise NotFoundError("Пакет заявки не найден")

    mentions = sorted(set(MENTION_RE.findall(payload.body)))
    comment = Comment(
        request_id=request_id,
        request_item_id=payload.request_item_id,
        author_id=user.id,
        author_role=primary_role(user),
        body=payload.body.strip(),
        mentions=mentions or None,
    )
    session.add(comment)
    session.flush()

    audit.record(
        session,
        action="comment_added",
        entity_type="comment",
        entity_id=comment.id,
        actor=user,
        new_value={"request_id": request_id, "request_item_id": payload.request_item_id},
        source="ui",
    )
    _notify(session, comment, request, user, mentions)
    session.commit()
    return _payload(comment, user)


def _notify(
    session: Session,
    comment: Comment,
    request: ModerationRequest,
    author: User,
    mentions: list[str],
) -> None:
    notifier = get_notifier()
    label = f"заявка #{request.id}"
    message = NotificationMessage(
        event=Event.COMMENT_ADDED,
        title=f"{EVENT_TITLES[Event.COMMENT_ADDED]}: {label}",
        body=f"{author.display_name}: {comment.body[:200]}",
        request_id=request.id,
        request_item_id=comment.request_item_id,
        payload={"comment_id": comment.id, "mentions": mentions},
    )
    recipients: list[int] = []
    if request.author_id != author.id:
        recipients.append(request.author_id)
    if mentions:
        mentioned = session.execute(
            select(User).where(User.username.in_(mentions))
        ).scalars().all()
        recipients.extend(u.id for u in mentioned if u.id != author.id)
    # Участники обсуждения, уже писавшие в ветку.
    prior = session.execute(
        select(Comment.author_id).where(Comment.request_id == request.id)
    ).scalars().all()
    recipients.extend(uid for uid in prior if uid != author.id)
    notifier.notify_users(session, recipients, message)


@router.patch("/comments/{comment_id}", response_model=CommentOut, summary="Изменить сообщение")
def edit_comment(
    comment_id: int,
    payload: CommentUpdateIn,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CommentOut:
    comment = _own_comment(session, comment_id, user)
    s = get_settings()
    old_body = comment.body
    created = comment.created_at
    now = utcnow()
    if created.tzinfo is None:
        created = created.replace(tzinfo=now.tzinfo)
    within_window = now - created <= timedelta(minutes=s.comment_edit_window_minutes)

    comment.body = payload.body.strip()
    if not within_window:
        # Позже окна правки — только пометка «изменено» с записью в аудит.
        comment.is_edited = True
        comment.edited_at = now
    audit.record(
        session,
        action="comment_edited",
        entity_type="comment",
        entity_id=comment.id,
        actor=user,
        old_value={"body": old_body},
        new_value={"body": comment.body, "marked_edited": comment.is_edited},
        source="ui",
    )
    session.commit()
    return _payload(comment, user)


@router.delete("/comments/{comment_id}", response_model=CommentOut, summary="Удалить сообщение")
def delete_comment(
    comment_id: int,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CommentOut:
    comment = _own_comment(session, comment_id, user)
    comment.deleted_at = utcnow()
    audit.record(
        session,
        action="comment_deleted",
        entity_type="comment",
        entity_id=comment.id,
        actor=user,
        old_value={"body": comment.body},
        new_value={"deleted": True},
        source="ui",
    )
    session.commit()
    return _payload(comment, user)


def _own_comment(session: Session, comment_id: int, user: User) -> Comment:
    comment = session.get(Comment, comment_id)
    if comment is None:
        raise NotFoundError(f"Сообщение #{comment_id} не найдено")
    if comment.deleted_at is not None:
        raise ValidationError("Сообщение уже удалено")
    if comment.author_id != user.id and not user.has_role("admin"):
        raise ForbiddenError("Изменять и удалять можно только свои сообщения")
    return comment
