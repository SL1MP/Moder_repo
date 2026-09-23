"""Промежуточная зона вместо S3: столбцы artifact называются по существу

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-23 10:20:00.000000+00:00

Отказ от S3 (решение пользователя) меняет не только реализацию хранилища, но и
смысл этих столбцов. Раньше в них лежали бакет и ключ объекта в S3-совместимом
хранилище; теперь — репозиторий артефактори и путь файла в нём. Оставить имена
s3_* значило бы завести в схеме ложь ровно того сорта, который этот проект уже
ловил дважды: имя, рассказывающее про выведенную из эксплуатации систему,
отправляет искать проблему не туда.

Атрибуты модели python-версии (Artifact.s3_key и прочие) при этом сохранены и
просто указывают на новые столбцы: их читает весь остальной код, а python-версия
доживает до конца переноса на Go.

ALTER ... RENAME COLUMN не переписывает таблицу и не берёт долгой блокировки:
меняется только запись в каталоге.

Парная миграция golang-migrate — backend-go/migrations/0015_staging_columns.
"""
from __future__ import annotations

from alembic import op

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | None = None
depends_on: str | None = None

# (таблица, старое имя, новое имя)
_RENAMES = (
    ('artifact', 's3_bucket', 'staging_repo'),
    ('artifact', 's3_key', 'staging_path'),
    ('artifact', 's3_uploaded_at', 'staged_at'),
    ('artifact', 's3_deleted_at', 'staging_cleared_at'),
    ('scan_report', 'bucket', 'repo'),
)


def _rename(table: str, old: str, new: str) -> None:
    """Переименование, безопасное к повторному прогону.

    Набор миграций накатывается руками, и второй прогон не должен падать на
    столбце, который уже переименован.
    """
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = '{table}' AND column_name = '{old}') THEN
                ALTER TABLE {table} RENAME COLUMN {old} TO {new};
            END IF;
        END $$
        """
    )


def upgrade() -> None:
    for table, old, new in _RENAMES:
        _rename(table, old, new)

    # Пути в промежуточной зоне остались прежними по форме
    # ({manager}/{name}/{version}/{filename}), а вот репозиторий сменился: в
    # столбце лежит имя бакета S3, которого больше нет. Ставим NULL — «где
    # лежал, неизвестно» честнее, чем имя несуществующего бакета, и уборка по
    # таким строкам всё равно идёт по пути, а не по репозиторию.
    op.execute(
        "UPDATE artifact SET staging_repo = NULL "
        "WHERE staging_cleared_at IS NULL AND staging_repo IS NOT NULL"
    )


def downgrade() -> None:
    # Значения не восстанавливаются: какой бакет S3 стоял в staging_repo до
    # миграции, нигде не сохранено. Откат возвращает форму схемы, а не данные.
    for table, old, new in _RENAMES:
        _rename(table, new, old)
