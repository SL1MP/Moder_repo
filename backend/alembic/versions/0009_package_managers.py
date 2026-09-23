"""Полный набор пакетных менеджеров

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-23 10:10:00.000000+00:00

Было четыре менеджера (pypi, npm, go, nuget) — те, что перенёс прототип.
Добавляются восемь: conan, docker, luarocks, maven, php, terraform, git, files.
Поддержка всех видов модерации — обязательный скоуп сервиса, а не бэклог
(docs/ci-parity-gaps.md).

Два последних кода стоят особняком: git — модерация git-репозитория целиком,
files — модерация готового архива или двоичного файла, который разработчик
приносит сам. У обоих нет ни реестра, ни канонической версии.

VARCHAR(16) не трогаем: самый длинный новый код — terraform (9 символов).

Парная миграция golang-migrate — backend-go/migrations/0014_package_managers.
Держать обе обязательно — см. комментарий в 0005.

Список значений записан литералом намеренно — см. комментарий в 0004.
"""
from __future__ import annotations

from alembic import op

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | None = None
depends_on: str | None = None

_ALL = (
    "'pypi', 'npm', 'go', 'nuget', "
    "'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform', "
    "'git', 'files'"
)
_PROTOTYPE = "'pypi', 'npm', 'go', 'nuget'"


def _drop_all_names() -> None:
    """Снимает ограничения, как бы их ни назвал создавший базу набор миграций."""
    op.execute("ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager")
    # Настоящее имя из NAMING_CONVENTION (см. app/db/base.py). Без него старое
    # запрещающее ограничение остаётся рядом с новым разрешающим, и запись
    # отвергается по нему, хотя миграция прошла успешно.
    op.execute("ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager_code")
    op.execute("ALTER TABLE package DROP CONSTRAINT IF EXISTS package_manager_check")
    op.execute("ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager")
    op.execute("ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager_code")
    op.execute("ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_manager_check")
    op.execute("ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_code")
    op.execute("ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_manager_code")
    op.execute("ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS package_manager_code_check")


def _apply(values: str) -> None:
    op.create_check_constraint('manager', 'package', f"manager IN ({values})")
    op.create_check_constraint('manager', 'moderation_request', f"manager IN ({values})")
    op.create_check_constraint('code', 'package_manager', f"code IN ({values})")


def upgrade() -> None:
    _drop_all_names()
    _apply(_ALL)

    # Справочник менеджеров для выпадающего списка в интерфейсе. Строки пишем
    # здесь, а не оставляем на bootstrap: справочник читают обе версии сервиса,
    # и пустой он означает пустой список менеджеров на странице заведения
    # пакетов.
    #
    # ON CONFLICT DO NOTHING, а не UPDATE: заголовок и формат записи
    # администратор мог поправить под себя, и миграция не вправе это затирать.
    op.execute(
        """
        INSERT INTO package_manager (code, title, entry_format, enabled) VALUES
            ('maven',     'Maven',     'groupId:artifactId:version', true),
            ('docker',    'Docker',    'image:tag',                  true),
            ('conan',     'Conan',     'name/version',               true),
            ('luarocks',  'LuaRocks',  'rock version',               true),
            ('terraform', 'Terraform', 'namespace/name version',     true),
            ('php',       'PHP',       'vendor/package:version',     true),
            ('git',       'Git',       'url@ref',                    true),
            ('files',     'Файлы',     'url@sha256:<хеш>',           true)
        ON CONFLICT (code) DO NOTHING
        """
    )


def downgrade() -> None:
    # Пакеты новых менеджеров удаляются, а не остаются нарушать ограничение.
    # Удаление каскадное по внешним ключам (package_version → request_item →
    # pipeline_step), поэтому вместе с пакетом уходит и история его проверок —
    # это и есть цена отката, и умолчать о ней нельзя.
    op.execute(f"DELETE FROM moderation_request WHERE manager NOT IN ({_PROTOTYPE})")
    op.execute(f"DELETE FROM package WHERE manager NOT IN ({_PROTOTYPE})")
    op.execute(f"DELETE FROM package_manager WHERE code NOT IN ({_PROTOTYPE})")

    _drop_all_names()
    _apply(_PROTOTYPE)
