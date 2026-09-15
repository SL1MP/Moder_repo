"""Находки сканеров содержимого: политические баннеры и SAST

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-27 13:40:00.000000+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        'code_finding',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('package_version_id', sa.Integer(), nullable=False),
        sa.Column('scanner', sa.String(length=32), nullable=False),
        sa.Column('rule_id', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('file_path', sa.String(length=1024), nullable=True),
        sa.Column('line', sa.Integer(), nullable=True),
        sa.Column('matched', sa.Text(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ['package_version_id'], ['package_version.id'],
            name=op.f('fk_code_finding_package_version_id_package_version'),
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_code_finding')),
    )
    op.create_index('ix_code_finding_package_version_id', 'code_finding', ['package_version_id'])
    op.create_index('ix_code_finding_scanner', 'code_finding', ['scanner'])


def downgrade() -> None:
    op.drop_index('ix_code_finding_scanner', table_name='code_finding')
    op.drop_index('ix_code_finding_package_version_id', table_name='code_finding')
    op.drop_table('code_finding')
