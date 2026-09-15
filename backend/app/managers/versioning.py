"""Сравнение версий по правилам экосистем и сопоставление с диапазонами OSV.

Каждая экосистема считает версии по-своему, поэтому у диапазонов OSV нет общего
компаратора: `1.0.0-rc1 < 1.0.0` в semver, `1.0rc1 < 1.0` в PEP 440,
`1.0.0-rc.1 < 1.0.0` в NuGet, а Go добавляет префикс `v` и `+incompatible`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from functools import cmp_to_key
from typing import Any

from packaging.version import InvalidVersion, Version

Comparator = Callable[[str, str], int]


def _cmp(a: Any, b: Any) -> int:
    return (a > b) - (a < b)


# --------------------------------------------------------------------------- PEP 440
def compare_pep440(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return _cmp(a, b)
    return _cmp(va, vb)


# --------------------------------------------------------------------------- SemVer
_SEMVER_RE = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+(?P<build>[0-9A-Za-z.\-]+))?$"
)


def _semver_parts(v: str) -> tuple[tuple[int, int, int], list[str]] | None:
    m = _SEMVER_RE.match(v.strip())
    if not m:
        return None
    core = (
        int(m.group("major")),
        int(m.group("minor") or 0),
        int(m.group("patch") or 0),
    )
    pre = m.group("pre")
    return core, (pre.split(".") if pre else [])


def _cmp_prerelease(a: list[str], b: list[str]) -> int:
    """Пустой prerelease старше любого непустого (1.0.0 > 1.0.0-rc.1)."""
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for x, y in zip(a, b, strict=False):
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            c = _cmp(int(x), int(y))
        elif xd != yd:
            c = -1 if xd else 1  # числовые идентификаторы младше алфавитных
        else:
            c = _cmp(x, y)
        if c:
            return c
    return _cmp(len(a), len(b))


def compare_semver(a: str, b: str) -> int:
    pa, pb = _semver_parts(a), _semver_parts(b)
    if pa is None or pb is None:
        return _cmp(a, b)
    c = _cmp(pa[0], pb[0])
    return c if c else _cmp_prerelease(pa[1], pb[1])


# --------------------------------------------------------------------------- Go
def compare_go(a: str, b: str) -> int:
    """Go-модули: `vX.Y.Z`, `+incompatible`, псевдоверсии `v0.0.0-2024...-abcdef`."""
    return compare_semver(a.replace("+incompatible", ""), b.replace("+incompatible", ""))


# --------------------------------------------------------------------------- NuGet
_NUGET_RE = re.compile(
    r"^(?P<nums>\d+(?:\.\d+){0,3})(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$"
)


def compare_nuget(a: str, b: str) -> int:
    ma, mb = _NUGET_RE.match(a.strip()), _NUGET_RE.match(b.strip())
    if not ma or not mb:
        return _cmp(a, b)
    na = [int(x) for x in ma.group("nums").split(".")]
    nb = [int(x) for x in mb.group("nums").split(".")]
    while len(na) < 4:
        na.append(0)
    while len(nb) < 4:
        nb.append(0)
    c = _cmp(na, nb)
    if c:
        return c
    pa = ma.group("pre").split(".") if ma.group("pre") else []
    pb = mb.group("pre").split(".") if mb.group("pre") else []
    return _cmp_prerelease(pa, pb)


COMPARATORS: dict[str, Comparator] = {
    "pypi": compare_pep440,
    "npm": compare_semver,
    "go": compare_go,
    "nuget": compare_nuget,
}

# Экосистемы в терминах OSV.
OSV_ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "nuget": "NuGet",
}
MANAGER_BY_ECOSYSTEM: dict[str, str] = {v.lower(): k for k, v in OSV_ECOSYSTEMS.items()}


def get_comparator(manager: str) -> Comparator:
    return COMPARATORS.get(manager, lambda a, b: _cmp(a, b))


def sort_versions(manager: str, versions: Iterable[str], *, reverse: bool = False) -> list[str]:
    return sorted(versions, key=cmp_to_key(get_comparator(manager)), reverse=reverse)


def version_matches_range(manager: str, version: str, osv_range: dict[str, Any]) -> bool:
    """Проверяет попадание версии в один `ranges[]`-элемент записи OSV.

    Диапазон задан цепочкой событий `introduced` / `fixed` / `last_affected`,
    отсортированной по возрастанию. Версия затронута, если после последнего
    применимого `introduced` не было `fixed`/`last_affected`, её отсекающего.
    """
    cmp = get_comparator(manager)
    events: Sequence[dict[str, str]] = osv_range.get("events") or []
    affected = False
    for event in events:
        if "introduced" in event:
            intro = event["introduced"]
            if intro == "0" or cmp(version, intro) >= 0:
                affected = True
        elif "fixed" in event:
            if cmp(version, event["fixed"]) >= 0:
                affected = False
        elif "last_affected" in event:
            if cmp(version, event["last_affected"]) > 0:
                affected = False
    return affected


def version_is_affected(manager: str, version: str, affected_entry: dict[str, Any]) -> bool:
    """Проверяет `affected[]`-запись OSV целиком: список `versions` + `ranges`."""
    cmp = get_comparator(manager)
    explicit = affected_entry.get("versions") or []
    if explicit and any(cmp(version, v) == 0 for v in explicit):
        return True
    ranges = affected_entry.get("ranges") or []
    for rng in ranges:
        if rng.get("type") == "GIT":
            continue  # git-диапазоны не применимы к версиям реестра
        if version_matches_range(manager, version, rng):
            return True
    # Если ranges нет вовсе, а versions задан и не совпал — не затронуто.
    return False


def extract_fixed_versions(affected_entry: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for rng in affected_entry.get("ranges") or []:
        for event in rng.get("events") or []:
            if "fixed" in event:
                fixed.append(event["fixed"])
    return fixed
