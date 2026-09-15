"""Коды шагов banner_scan и sast_scan в CHECK-ограничении

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-27 14:30:00.000000+00:00

Шаги «Политические баннеры» и «SAST-анализ» добавлены в STEP_CODES, но список
допустимых кодов хранится ещё и в CHECK-ограничении таблицы pipeline_step.
Модель строит его из константы, а база — из миграции, поэтому расхождение
тестами не ловилось: схема в тестах поднимается из моделей. В бою вставка
строки шага падала с

    CheckViolation: new row for relation "pipeline_step"
    violates check constraint "ck_pipeline_step_step_code"

и заявка не создавалась вовсе.

Списки кодов записаны литералами намеренно: миграция — снимок состояния на
своей ревизии, и вычислять его из константы нельзя, иначе смысл уже
применённой миграции менялся бы вместе с кодом.
"""
from __future__ import annotations

from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # op.f() обязателен: имя уже содержит префикс соглашения об именовании.
    # Без него alembic навесит `ck_pipeline_step_` второй раз и попытается
    # удалить несуществующее `ck_pipeline_step_ck_pipeline_step_step_code`.
    op.drop_constraint(op.f('ck_pipeline_step_step_code'), 'pipeline_step', type_='check')
    op.create_check_constraint(
        'step_code',
        'pipeline_step',
        "step_code IN ('db_check', 'blacklist', 'quarantine', 'license', 'download', "
        "'vuln_scan', 'banner_scan', 'sast_scan', 'publish')",
    )


def downgrade() -> None:
    # Строки новых шагов пришлось бы удалить, иначе старое ограничение не
    # применится: значения, которых в нём нет, уже лежат в таблице.
    op.execute("DELETE FROM pipeline_step WHERE step_code IN ('banner_scan', 'sast_scan')")
    op.drop_constraint(op.f('ck_pipeline_step_step_code'), 'pipeline_step', type_='check')
    op.create_check_constraint(
        'step_code',
        'pipeline_step',
        "step_code IN ('db_check', 'blacklist', 'quarantine', 'license', 'download', "
        "'vuln_scan', 'publish')",
    )
