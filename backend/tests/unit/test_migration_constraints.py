"""CHECK-ограничения в миграциях должны совпадать с константами в коде.

Модель строит ограничение из константы (`_in("step_code", STEP_CODES)`), а
миграция хранит список значений текстом. Тесты поднимают схему из моделей,
поэтому расхождение между ними тестами не ловится вообще: добавили код шага в
Python — тесты зелёные, а боевая база, созданная миграцией, отвергает вставку
с `CheckViolation`. Ровно так шаги `banner_scan` и `sast_scan` дошли до прода.

Этот тест сверяет то, что реально окажется в базе после миграций, с тем, что
использует код.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from app.db.enums import (
    ARTIFACT_STATUSES,
    CLAIM_STATUSES,
    DEPENDENCY_KINDS,
    ITEM_STATUSES,
    MANAGER_CODES,
    REQUEST_SOURCES,
    REQUEST_STATUSES,
    STEP_CODES,
    STEP_RESULTS,
    VERSION_STATUSES,
)

MIGRATIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"

# Имя ограничения в базе -> набор значений, которым пользуется код.
EXPECTED: dict[str, tuple[str, ...]] = {
    "ck_pipeline_step_step_code": STEP_CODES,
    "ck_pipeline_step_step_result": STEP_RESULTS,
    "ck_package_version_version_status": VERSION_STATUSES,
    "ck_request_item_item_status": ITEM_STATUSES,
    "ck_request_item_dependency_kind": DEPENDENCY_KINDS,
    "ck_moderation_request_request_status": REQUEST_STATUSES,
    "ck_moderation_request_request_source": REQUEST_SOURCES,
    "ck_moderation_request_manager_code": MANAGER_CODES,
    "ck_package_manager_code": MANAGER_CODES,
    "ck_package_manager_manager_code": MANAGER_CODES,
    "ck_license_claim_claim_status": CLAIM_STATUSES,
    "ck_artifact_artifact_status": ARTIFACT_STATUSES,
}

# Разбираем объявления точно по структуре вызова, а не по окну текста: списки
# соседних ограничений идут вплотную, и поиск «ближайшего IN» хватает чужой.
#   sa.CheckConstraint("step_code IN ('a','b')", name=op.f('ck_pipeline_step_step_code'))
_INLINE = re.compile(
    r"sa\.CheckConstraint\(\s*\"(?P<expr>[^\"]*)\"\s*,\s*name=op\.f\(\'(?P<name>[^\']+)\'\)"
)
#   op.create_check_constraint('step_code', 'pipeline_step', "step_code IN ('a','b')")
# Выражение всегда в двойных кавычках и содержит одинарные ('a', 'b'), поэтому
# для него отдельный класс: [^'"] обрывался бы на первом же значении.
_CREATE = re.compile(
    r"op\.create_check_constraint\(\s*'(?P<short>[^']+)'\s*,"
    r"\s*'(?P<table>[^']+)'\s*,\s*\"(?P<expr>[^\"]*)\""
)
_VALUES = re.compile(r"IN \(([^)]*)\)")


def _values(expr: str) -> set[str] | None:
    found = _VALUES.search(expr)
    if not found:
        return None
    return {v.strip().strip("'\"") for v in found.group(1).split(",") if v.strip()}


def _migration_text() -> str:
    """Только тела upgrade(): в downgrade() лежит прежнее состояние схемы.

    Без этого разбор брал бы последнее объявление в файле — то есть откат, — и
    считал бы актуальным как раз тот список, от которого миграция уходит.
    """
    parts: list[str] = []
    for path in sorted(MIGRATIONS.glob("0*.py")):
        text = path.read_text(encoding="utf-8")
        head, _, _ = text.partition("def downgrade")
        # Длинное условие в миграции обычно разбито на соседние литералы
        # ("...IN ('a', " "'b')") — Python склеит их сам, а разбору нужно
        # видеть строку целиком.
        head = re.sub(r'"\s*\n?\s*"', "", head)
        parts.append(head)
    return "\n".join(parts)


def _declared(text: str) -> dict[str, set[str]]:
    """Имя ограничения -> набор значений по последнему объявлению."""
    out: dict[str, set[str]] = {}
    for match in _INLINE.finditer(text):
        values = _values(match.group("expr"))
        if values:
            out[match.group("name")] = values
    for match in _CREATE.finditer(text):
        values = _values(match.group("expr"))
        if values:
            out[f"ck_{match.group('table')}_{match.group('short')}"] = values
    return out


@pytest.mark.parametrize(("constraint", "expected"), sorted(EXPECTED.items()))
def test_migration_constraint_matches_code(constraint: str, expected: tuple[str, ...]):
    declared = _declared(_migration_text()).get(constraint)
    if declared is None:
        pytest.skip(f"ограничение {constraint} в миграциях не встречается")

    missing = set(expected) - declared
    extra = declared - set(expected)
    assert not missing, (
        f"{constraint}: значения есть в коде, но не разрешены миграцией — {sorted(missing)}. "
        "Нужна миграция, обновляющая CHECK, иначе база отвергнет вставку."
    )
    assert not extra, f"{constraint}: миграция разрешает то, чего нет в коде — {sorted(extra)}"


def test_step_codes_are_covered():
    """Отдельно и явно: именно на этом ограничении сервис уже падал в бою."""
    declared = _declared(_migration_text()).get("ck_pipeline_step_step_code")

    assert declared == set(STEP_CODES)


# --------------------------------------------------------------- рендер SQL
# Всё выше сверяет тексты. Этого мало: миграция может быть согласована с кодом
# и при этом порождать неверный SQL. Так и вышло с 0004 — имя ограничения было
# передано без op.f(), соглашение об именовании навесило префикс второй раз, и
# alembic попытался удалить `ck_pipeline_step_ck_pipeline_step_step_code`.
# Ошибка вылезла только в бою: PostgreSQL здесь нет.
#
# Офлайн-режим alembic рендерит SQL без подключения к базе, поэтому такую
# ошибку видно и без неё.

def _render(command: str) -> str:
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    done = subprocess.run(
        [sys.executable, "-m", "alembic", *command.split()],
        cwd=root,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "DATABASE_URL": "postgresql+psycopg://user:pass@db/moderation",
        },
    )
    assert done.returncode == 0, f"alembic не отработал:\n{done.stderr[-1500:]}"
    return done.stdout


def test_migrations_render_to_sql():
    """Все миграции должны разворачиваться в SQL без ошибок."""
    sql = _render("upgrade base:head --sql")

    assert "CREATE TABLE pipeline_step" in sql
    assert "CREATE TABLE code_finding" in sql


def test_constraint_names_are_not_doubled():
    """Имя ограничения не должно получать префикс соглашения дважды."""
    sql = _render("upgrade base:head --sql")

    doubled = re.findall(r"\b(\w*?(ck|fk|uq|ix)_\w+_\2_\w+)\b", sql)
    assert not doubled, f"имя собрано с удвоенным префиксом: {sorted({d[0] for d in doubled})}"


def test_step_code_constraint_in_rendered_sql():
    """В базе после миграций должны быть разрешены все коды шагов из кода."""
    sql = _render("upgrade base:head --sql")

    # Последнее по порядку определение ограничения — актуальное.
    definitions = re.findall(
        r"ADD CONSTRAINT ck_pipeline_step_step_code CHECK \(step_code IN \(([^)]*)\)\)", sql
    )
    assert definitions, "ограничение на step_code в SQL не найдено"
    allowed = {v.strip().strip("'") for v in definitions[-1].split(",")}

    assert allowed == set(STEP_CODES)
