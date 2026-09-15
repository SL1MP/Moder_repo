"""Парсеры файлов зависимостей NuGet: packages.lock.json, packages.config, *.csproj."""

from __future__ import annotations

import json
import re
from typing import Any
from xml.etree import ElementTree

from app.core.errors import InvalidPackageFormat
from app.managers.parsers import RawDependency

_EXACT = re.compile(r"^\d+(\.\d+){0,3}(-[0-9A-Za-z.\-]+)?$")


def parse_packages_lock_json(content: bytes) -> list[RawDependency]:
    """packages.lock.json: `type` = Direct | Transitive | Project."""
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise InvalidPackageFormat(f"Файл packages.lock.json не является корректным JSON: {exc}") from exc
    out: list[RawDependency] = []
    targets: dict[str, Any] = data.get("dependencies") or {}
    for packages in targets.values():
        if not isinstance(packages, dict):
            continue
        for name, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            dep_type = str(meta.get("type", "")).lower()
            if dep_type == "project":
                continue
            version = meta.get("resolved") or meta.get("requested")
            if not version:
                continue
            kind = "direct" if dep_type == "direct" else "transitive"
            out.append(RawDependency(name=name, version=str(version), kind=kind))
    if not out:
        raise InvalidPackageFormat("В packages.lock.json не найдено зависимостей")
    return _dedupe(out)


def parse_packages_config(content: bytes) -> list[RawDependency]:
    """packages.config: `<package id="..." version="..." />`."""
    root = _parse_xml(content, "packages.config")
    out: list[RawDependency] = []
    for node in root.iter():
        if _localname(node.tag) != "package":
            continue
        name = node.get("id")
        version = node.get("version")
        if name and version:
            out.append(RawDependency(name=name, version=version))
    if not out:
        raise InvalidPackageFormat("В packages.config не найдено элементов <package>")
    return out


def parse_csproj(content: bytes) -> list[RawDependency]:
    """*.csproj: `<PackageReference Include="..." Version="..." />`."""
    root = _parse_xml(content, "*.csproj")
    out: list[RawDependency] = []
    for node in root.iter():
        tag = _localname(node.tag)
        if tag not in {"PackageReference", "PackageVersion", "PackageDownload"}:
            continue
        name = node.get("Include") or node.get("Update")
        version = node.get("Version")
        if version is None:
            child = next(
                (c for c in node if _localname(c.tag) == "Version" and (c.text or "").strip()), None
            )
            version = child.text.strip() if child is not None and child.text else None
        if not name:
            continue
        if not version:
            out.append(
                RawDependency(
                    name=name,
                    version="",
                    note=f"«{name}»: версия задана переменной или отсутствует; укажите её явно",
                )
            )
            continue
        version = version.strip()
        if version.startswith("$(") or not _EXACT.match(version.strip("[]()")):
            out.append(
                RawDependency(
                    name=name,
                    version="",
                    note=f"«{name}»: «{version}» — не точная версия; укажите её явно",
                )
            )
            continue
        out.append(RawDependency(name=name, version=version.strip("[]()")))
    if not out:
        raise InvalidPackageFormat("В файле проекта не найдено элементов <PackageReference>")
    return out


def _parse_xml(content: bytes, filename: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(content)  # noqa: S314 - вход валидируется размером и ролью
    except ElementTree.ParseError as exc:
        raise InvalidPackageFormat(f"Файл {filename} не является корректным XML: {exc}") from exc


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _dedupe(deps: list[RawDependency]) -> list[RawDependency]:
    best: dict[tuple[str, str], RawDependency] = {}
    for dep in deps:
        key = (dep.name.lower(), dep.version)
        existing = best.get(key)
        if existing is None or (existing.kind == "transitive" and dep.kind == "direct"):
            best[key] = dep
    return list(best.values())
