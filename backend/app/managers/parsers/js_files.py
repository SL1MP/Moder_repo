"""Парсеры файлов зависимостей npm: package-lock.json, yarn.lock, package.json."""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.errors import InvalidPackageFormat
from app.managers.parsers import RawDependency

_EXACT = re.compile(r"^\d+\.\d+\.\d+")


def parse_package_lock(content: bytes) -> list[RawDependency]:
    """package-lock.json v1/v2/v3. Прямые зависимости — из корневого `packages[""]`."""
    data = _load_json(content, "package-lock.json")
    out: list[RawDependency] = []
    direct: set[str] = set()

    packages: dict[str, Any] = data.get("packages") or {}
    root = packages.get("")
    if isinstance(root, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            direct.update((root.get(section) or {}).keys())
    else:
        for section in ("dependencies", "devDependencies"):
            direct.update((data.get(section) or {}).keys())

    if packages:  # lockfileVersion 2/3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or _name_from_lock_path(path)
            version = meta.get("version")
            if not name or not version:
                continue
            kind = "direct" if name in direct else "transitive"
            out.append(RawDependency(name=name, version=version, kind=kind))
    else:  # lockfileVersion 1
        _walk_v1(data.get("dependencies") or {}, direct, out, top=True)
    return _dedupe(out)


def _name_from_lock_path(path: str) -> str | None:
    marker = "node_modules/"
    idx = path.rfind(marker)
    if idx == -1:
        return None
    return path[idx + len(marker) :] or None


def _walk_v1(
    tree: dict[str, Any], direct: set[str], out: list[RawDependency], *, top: bool = False
) -> None:
    for name, meta in tree.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if version:
            kind = "direct" if (top and name in direct) or name in direct else "transitive"
            out.append(RawDependency(name=name, version=version, kind=kind))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(nested, direct, out)


def parse_yarn_lock(content: bytes) -> list[RawDependency]:
    """yarn.lock: классический (v1) текстовый формат и YAML-подобный berry (v2+)."""
    text = content.decode("utf-8", errors="replace")
    out: list[RawDependency] = []
    current_names: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            current_names = _yarn_spec_names(line.rstrip()[:-1])
            continue
        stripped = line.strip()
        if stripped.startswith("version") and current_names:
            value = stripped.split(":", 1)[1] if ":" in stripped else stripped.split(" ", 1)[1]
            version = value.strip().strip('",')
            for name in current_names:
                out.append(RawDependency(name=name, version=version, kind="transitive"))
            current_names = []
    if not out:
        raise InvalidPackageFormat("Не удалось разобрать yarn.lock: не найдено ни одной записи")
    return _dedupe(out)


def _yarn_spec_names(header: str) -> list[str]:
    names: list[str] = []
    for chunk in header.split(","):
        spec = chunk.strip().strip('"')
        if not spec:
            continue
        scoped = spec.startswith("@")
        body = spec[1:] if scoped else spec
        name = body.split("@", 1)[0]
        names.append(("@" + name) if scoped else name)
    return [n for n in names if n]


def parse_package_json(content: bytes) -> list[RawDependency]:
    data = _load_json(content, "package.json")
    out: list[RawDependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = str(spec).strip()
            if _EXACT.match(version):
                out.append(RawDependency(name=name, version=version))
            else:
                out.append(
                    RawDependency(
                        name=name,
                        version="",
                        note=f"«{name}»: «{version}» — диапазон версий; укажите точную версию",
                    )
                )
    return out


def _dedupe(deps: list[RawDependency]) -> list[RawDependency]:
    """Одна запись на (имя, версия); `direct` имеет приоритет над `transitive`."""
    best: dict[tuple[str, str], RawDependency] = {}
    for dep in deps:
        key = (dep.name, dep.version)
        existing = best.get(key)
        if existing is None or (existing.kind == "transitive" and dep.kind == "direct"):
            best[key] = dep
    return list(best.values())


def _load_json(content: bytes, filename: str) -> dict[str, Any]:
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise InvalidPackageFormat(f"Файл {filename} не является корректным JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidPackageFormat(f"Файл {filename} должен содержать JSON-объект")
    return data
