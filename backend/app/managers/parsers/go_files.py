"""Парсеры файлов зависимостей Go: go.mod, go.sum."""

from __future__ import annotations

import re

from app.core.errors import InvalidPackageFormat
from app.managers.parsers import RawDependency

_REQUIRE_LINE = re.compile(r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s]+)(?P<rest>.*)$")


def parse_go_mod(content: bytes) -> list[RawDependency]:
    """go.mod: блоки `require`; `// indirect` отмечает транзитивную зависимость."""
    out: list[RawDependency] = []
    in_block = False
    found_module = False

    for raw_line in content.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("module "):
            found_module = True
            continue
        if line.startswith("require") and line.endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        payload = line
        if line.startswith("require "):
            payload = line[len("require ") :].strip()
        elif not in_block:
            continue
        comment = ""
        if "//" in payload:
            payload, comment = payload.split("//", 1)
            payload = payload.strip()
        m = _REQUIRE_LINE.match(payload)
        if not m:
            continue
        kind = "transitive" if "indirect" in comment else "direct"
        out.append(RawDependency(name=m.group("module"), version=m.group("version"), kind=kind))

    if not out and not found_module:
        raise InvalidPackageFormat("Файл не похож на go.mod: нет директив module/require")
    return out


def parse_go_sum(content: bytes) -> list[RawDependency]:
    """go.sum: полный граф модулей, прямые и транзитивные не различаются.

    Записи помечаются `direct` намеренно. Формат не хранит признак прямой
    зависимости, и пометка `transitive` была бы утверждением, которого из файла
    не следует. Практическое последствие было тяжёлым: транзитивные записи
    отбрасываются, если заявка создана без `include_transitive`, — а раз в
    go.sum транзитивным помечалось всё, отбрасывался весь файл и заявка
    получалась пустой. Снаружи это выглядело как «go.sum не поддерживается».

    О том, что go.sum содержит весь граф модулей, а не только прямые
    зависимости, пользователь предупреждается при разборе заявки
    (см. app/services/requests_service.py).
    """
    out: list[RawDependency] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in content.decode("utf-8", errors="replace").splitlines():
        parts = raw_line.split()
        if len(parts) < 3:
            continue
        module, version = parts[0], parts[1]
        version = version.removesuffix("/go.mod")
        if not version.startswith("v"):
            continue
        key = (module, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(RawDependency(name=module, version=version, kind="direct"))
    if not out:
        raise InvalidPackageFormat("Не удалось разобрать go.sum: не найдено ни одной записи")
    return out
