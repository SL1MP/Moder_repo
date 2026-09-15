"""Абстракция уведомлений.

В этой версии реализована только `InAppNotifier` (непрочитанные события в UI,
счётчики в очередях, `GET /api/v1/notifications`). Внешние интеграции
(Mattermost, Telegram) не реализуются, но добавление вебхук-реализации не должно
требовать правок в бизнес-логике — она обращается только к этому интерфейсу.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import Notification, User

log = get_logger(__name__)


class Event:
    """Список событий сервиса."""

    REQUEST_AWAITS_SECURITY = "request_awaits_security"
    REQUEST_AWAITS_LEGAL = "request_awaits_legal"
    LICENSE_CLAIMED = "license_claimed"
    COMMENT_ADDED = "comment_added"
    DECISION_MADE = "decision_made"
    QUARANTINE_RELEASED = "quarantine_released"
    PACKAGE_REVOKED = "package_revoked"
    PACKAGE_APPROVED = "package_approved"
    PIPELINE_FAILED = "pipeline_failed"


EVENT_TITLES: dict[str, str] = {
    Event.REQUEST_AWAITS_SECURITY: "Заявка ждёт DevSecOps",
    Event.REQUEST_AWAITS_LEGAL: "Заявка ждёт юристов",
    Event.LICENSE_CLAIMED: "Заявлена лицензия",
    Event.COMMENT_ADDED: "Новое сообщение в обсуждении",
    Event.DECISION_MADE: "Принято решение по пакету",
    Event.QUARANTINE_RELEASED: "Карантин снят",
    Event.PACKAGE_REVOKED: "Пакет отозван",
    Event.PACKAGE_APPROVED: "Пакет одобрен",
    Event.PIPELINE_FAILED: "Ошибка проверки пакета",
}


@dataclass
class NotificationMessage:
    event: str
    title: str
    body: str | None = None
    request_id: int | None = None
    request_item_id: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)


class Notifier(ABC):
    @abstractmethod
    def notify_users(self, session: Session, user_ids: list[int], message: NotificationMessage) -> int:
        """Отправляет уведомление конкретным пользователям. Возвращает число доставок."""

    @abstractmethod
    def notify_roles(self, session: Session, roles: list[str], message: NotificationMessage) -> int:
        """Отправляет уведомление всем носителям ролей (очереди DevSecOps и юристов)."""


class InAppNotifier(Notifier):
    """Уведомления внутри сервиса: строки в таблице `notification`."""

    def notify_users(self, session: Session, user_ids: list[int], message: NotificationMessage) -> int:
        created = 0
        for uid in dict.fromkeys(uid for uid in user_ids if uid):
            session.add(
                Notification(
                    user_id=uid,
                    event=message.event,
                    title=message.title,
                    body=message.body,
                    request_id=message.request_id,
                    request_item_id=message.request_item_id,
                    payload=message.payload or None,
                    created_at=utcnow(),
                )
            )
            created += 1
        if created:
            session.flush()
        return created

    def notify_roles(self, session: Session, roles: list[str], message: NotificationMessage) -> int:
        recipients: list[int] = []
        for user in session.query(User).filter(User.is_active.is_(True)).all():
            if user.has_role(*roles):
                recipients.append(user.id)
        return self.notify_users(session, recipients, message)


_notifier: Notifier | None = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = InAppNotifier()
    return _notifier


def set_notifier(notifier: Notifier | None) -> None:
    global _notifier
    _notifier = notifier
