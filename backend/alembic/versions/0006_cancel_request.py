"""Статус cancelled: автор закрывает свою заявку

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-17 10:20:00.000000+00:00

Пакеты перестали быть нужны (взяли другую библиотеку, переписали код, ошиблись
версией), а заявка висит в очереди роли и выглядит как работа, которую кто-то
должен сделать. Своего статуса для этого не было, и закрыть заявку было нечем:
`rejected` — решение роли («нельзя»), а не отказ автора («уже не нужно»), и
путать их в отчётности нельзя.

Отмена — не удаление: строки остаются, аудит и обсуждение сохраняются.

Заодно в списки попадает `dry_run` для заявки: этот статус уже пишет go-версия
(парная миграция golang-migrate 0009), а здесь его не было — база, созданная
alembic, отвергала бы такую заявку. Свёртка статусов в python-версии dry_run
по-прежнему не выставляет (известное расхождение, см. docs/migration-to-go.md),
но отвергать чужую запись CHECK не должен.

Парная миграция golang-migrate — backend-go/migrations/0011_cancel_request.
Имена ограничений сняты по обоим соглашениям — см. 0005.

Списки значений записаны литералами намеренно — см. комментарий в 0004.
"""
from __future__ import annotations

from alembic import op

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | None = None
depends_on: str | None = None


def _drop_item_status() -> None:
    op.execute("ALTER TABLE request_item DROP CONSTRAINT IF EXISTS ck_request_item_item_status")
    op.execute("ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check")


def _drop_request_status() -> None:
    op.execute(
        "ALTER TABLE moderation_request "
        "DROP CONSTRAINT IF EXISTS ck_moderation_request_request_status"
    )
    op.execute(
        "ALTER TABLE moderation_request "
        "DROP CONSTRAINT IF EXISTS moderation_request_status_check"
    )


def upgrade() -> None:
    _drop_item_status()
    op.create_check_constraint(
        'item_status',
        'request_item',
        "status IN ('queued', 'running', 'quarantined', 'awaiting_legal', "
        "'license_claimed', 'awaiting_security', 'approved', 'dry_run', 'rejected', "
        "'revoked', 'blacklisted', 'cancelled', 'failed')",
    )
    _drop_request_status()
    op.create_check_constraint(
        'request_status',
        'moderation_request',
        "status IN ('pending', 'awaiting_security', 'awaiting_legal', 'quarantined', "
        "'approved', 'partially_approved', 'dry_run', 'rejected', 'cancelled', 'failed')",
    )


def downgrade() -> None:
    # Отменённые переводятся в rejected: другого «дальше не поедет» в прежней
    # схеме нет. Отличить их потом можно только по аудиту (request_cancelled).
    op.execute("UPDATE request_item SET status = 'rejected' WHERE status = 'cancelled'")
    op.execute("UPDATE moderation_request SET status = 'rejected' WHERE status = 'cancelled'")

    _drop_item_status()
    op.create_check_constraint(
        'item_status',
        'request_item',
        "status IN ('queued', 'running', 'quarantined', 'awaiting_legal', "
        "'license_claimed', 'awaiting_security', 'approved', 'dry_run', 'rejected', "
        "'revoked', 'blacklisted', 'failed')",
    )
    _drop_request_status()
    op.create_check_constraint(
        'request_status',
        'moderation_request',
        "status IN ('pending', 'awaiting_security', 'awaiting_legal', 'quarantined', "
        "'approved', 'partially_approved', 'dry_run', 'rejected', 'failed')",
    )
