"""Парсеры файлов зависимостей Python: requirements.txt, poetry.lock, pyproject.toml."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from app.core.errors import InvalidPackageFormat
from app.managers.parsers import RawDependency

_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*"
    r"(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>[=<>!~]=?[^;#]*)?"
    r"(?:;.*)?$"
)
_PIN = re.compile(r"^==\s*(?P<version>[^\s,]+)$")


def parse_requirements_txt(content: bytes) -> list[RawDependency]:
    """requirements.txt: только точные пины `name==version` могут быть заведены."""
    out: list[RawDependency] = []
    for raw_line in content.decode("utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # -r, -e, --hash и прочие директивы пропускаем
        if line.startswith(("http://", "https://", "git+")):
            continue
        line = line.split("--hash", 1)[0].strip().rstrip("\\").strip()
        m = _REQ_LINE.match(line)
        if not m:
            raise InvalidPackageFormat(f"Не удалось разобрать строку requirements.txt: «{raw_line.strip()}»")
        name = m.group("name")
        spec = (m.group("spec") or "").strip()
        pin = _PIN.match(spec)
        if not pin:
            out.append(
                RawDependency(
                    name=name,
                    version="",
                    note=(
                        f"«{line}» — версия не закреплена (`==`); укажите точную версию, "
                        "модерация выполняется для конкретной версии"
                    ),
                )
            )
            continue
        out.append(RawDependency(name=name, version=pin.group("version")))
    return out


def parse_poetry_lock(content: bytes) -> list[RawDependency]:
    """poetry.lock: `category`/`optional` не различают прямые и транзитивные,

    поэтому прямыми считаются пакеты, перечисленные в pyproject.toml; здесь всё
    помечается транзитивным, а вызывающий уточняет по pyproject при наличии.
    """
    data = _load_toml(content, "poetry.lock")
    out: list[RawDependency] = []
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            out.append(RawDependency(name=name, version=version, kind="transitive"))
    return out


def parse_pyproject_toml(content: bytes) -> list[RawDependency]:
    """pyproject.toml: PEP 621 `project.dependencies` и `tool.poetry.dependencies`."""
    data = _load_toml(content, "pyproject.toml")
    out: list[RawDependency] = []

    for dep in (data.get("project", {}) or {}).get("dependencies", []) or []:
        out.extend(parse_requirements_txt(dep.encode()))

    optional = (data.get("project", {}) or {}).get("optional-dependencies", {}) or {}
    for deps in optional.values():
        for dep in deps or []:
            out.extend(parse_requirements_txt(dep.encode()))

    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = _poetry_spec_version(spec)
        if version:
            out.append(RawDependency(name=name, version=version))
        else:
            out.append(
                RawDependency(
                    name=name,
                    version="",
                    note=f"«{name}» в pyproject.toml задан диапазоном; укажите точную версию",
                )
            )
    return out


def _poetry_spec_version(spec: Any) -> str | None:
    if isinstance(spec, str):
        value = spec.strip()
    elif isinstance(spec, dict):
        value = str(spec.get("version", "")).strip()
    else:
        return None
    if not value:
        return None
    if value[0].isdigit():
        return value  # точная версия без операторов
    if value.startswith("=="):
        return value[2:].strip()
    return None


def _load_toml(content: bytes, filename: str) -> dict[str, Any]:
    try:
        return tomllib.loads(content.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError as exc:
        raise InvalidPackageFormat(f"Файл {filename} не является корректным TOML: {exc}") from exc
