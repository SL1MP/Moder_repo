"""Решение DevSecOps «публиковать несмотря на уязвимости»

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-10 20:09:14.160392+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column('package_version', sa.Column('security_override_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('package_version', sa.Column('security_override_by_id', sa.Integer(), nullable=True))
    op.add_column('package_version', sa.Column('security_override_comment', sa.Text(), nullable=True))
    op.create_foreign_key(op.f('fk_package_version_security_override_by_id_user'), 'package_version', 'user', ['security_override_by_id'], ['id'])


def downgrade() -> None:
    op.drop_constraint(op.f('fk_package_version_security_override_by_id_user'), 'package_version', type_='foreignkey')
    op.drop_column('package_version', 'security_override_comment')
    op.drop_column('package_version', 'security_override_by_id')
    op.drop_column('package_version', 'security_override_at')
