"""Дерево зависимостей внутри заявки

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-18 09:00:00.000000+00:00

До сих пор транзитивная зависимость была в заявке таким же самостоятельным
пакетом, как заявленный, и по строке нельзя было сказать, кто её притащил.
Юристу и DevSecOps это нужно постоянно: «эта GPL пришла через вот тот пакет» —
другой разговор, чем «у нас в заявке GPL».

parent_item_id ссылается на строку той же таблицы: дерево, а не отдельная
сущность связи. ON DELETE SET NULL, а не CASCADE: удаление родителя не должно
уносить с собой промодерированные пакеты.

depth хранится, хотя выводится обходом: по нему делается выборка «только
прямые» без рекурсивного запроса на каждый показ карточки.

Парная миграция golang-migrate — backend-go/migrations/0012_dependency_tree.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column('request_item', sa.Column('parent_item_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_request_item_parent_item_id', 'request_item', 'request_item',
        ['parent_item_id'], ['id'], ondelete='SET NULL',
    )
    op.add_column(
        'request_item',
        sa.Column('depth', sa.SmallInteger(), nullable=False, server_default='0'),
    )
    # required_range — требование родителя как есть («^4.17.21», «>=2,<4»).
    # По нему в карточке видно, почему выбрана именно эта версия.
    op.add_column('request_item', sa.Column('required_range', sa.String(256), nullable=True))
    op.create_index('ix_request_item_parent_item_id', 'request_item', ['parent_item_id'])

    op.add_column('moderation_request', sa.Column('resolve_depth', sa.SmallInteger(), nullable=True))
    op.add_column('moderation_request', sa.Column('resolve_summary', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('moderation_request', 'resolve_summary')
    op.drop_column('moderation_request', 'resolve_depth')
    op.drop_index('ix_request_item_parent_item_id', table_name='request_item')
    op.drop_column('request_item', 'required_range')
    op.drop_column('request_item', 'depth')
    op.drop_constraint('fk_request_item_parent_item_id', 'request_item', type_='foreignkey')
    op.drop_column('request_item', 'parent_item_id')
