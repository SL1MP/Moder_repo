"""Blacklist и справочник разрешённых лицензий.

Оба — файлы конфигурации, монтируемые в контейнер. Сервис перечитывает их при
старте и по `POST /api/v1/admin/reload` (роль admin).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.managers.versioning import get_comparator

log = get_logger(__name__)


# --------------------------------------------------------------------------- blacklist
@dataclass
class BlacklistRule:
    manager: str | None  # None = любой менеджер
    name: str  # точное имя или glob
    versions: str = "*"  # `*`, точная версия или диапазон `>=1.0,<2.0`
    reason: str = "Пакет запрещён правилами blacklist"
    added_by: str | None = None
    added_at: str | None = None

    def matches(self, manager: str, name: str, version: str) -> bool:
        if self.manager and self.manager != manager:
            return False
        if not (self.name == name or fnmatch(name, self.name)):
            return False
        return _version_in_spec(manager, version, self.versions)

    def as_dict(self) -> dict[str, Any]:
        return {
            "manager": self.manager,
            "name": self.name,
            "versions": self.versions,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
        }


def _version_in_spec(manager: str, version: str, spec: str) -> bool:
    """Диапазон версий: `*`, `1.2.3`, `>=1.0`, `>=1.0,<2.0`, `<1.4.3`."""
    spec = (spec or "*").strip()
    if spec in ("*", "", "all", "any"):
        return True
    cmp = get_comparator(manager)
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        for op in (">=", "<=", "==", "!=", ">", "<"):
            if clause.startswith(op):
                bound = clause[len(op) :].strip()
                result = cmp(version, bound)
                ok = {
                    ">=": result >= 0,
                    "<=": result <= 0,
                    "==": result == 0,
                    "!=": result != 0,
                    ">": result > 0,
                    "<": result < 0,
                }[op]
                if not ok:
                    return False
                break
        else:
            if cmp(version, clause) != 0:
                return False
    return True


@dataclass
class Blacklist:
    rules: list[BlacklistRule] = field(default_factory=list)
    loaded_at: datetime | None = None
    path: str | None = None
    error: str | None = None

    def find(self, manager: str, name: str, version: str) -> BlacklistRule | None:
        for rule in self.rules:
            if rule.matches(manager, name, version):
                return rule
        return None


# --------------------------------------------------------------------------- лицензии
@dataclass
class LicensePolicy:
    allowed: dict[str, dict[str, Any]] = field(default_factory=dict)
    forbidden: dict[str, dict[str, Any]] = field(default_factory=dict)
    loaded_at: datetime | None = None
    path: str | None = None
    error: str | None = None

    def is_allowed(self, spdx: str | None) -> bool:
        if not spdx:
            return False
        key = spdx.strip().lower()
        if key in self.forbidden:
            return False
        if key in self.allowed:
            return True
        # Составное выражение `A OR B`: достаточно одной разрешённой лицензии.
        if " or " in key:
            return any(self.is_allowed(part.strip(" ()")) for part in key.split(" or "))
        if " and " in key:
            return all(self.is_allowed(part.strip(" ()")) for part in key.split(" and "))
        return False

    def known_ids(self) -> list[str]:
        return sorted({v["spdx_id"] for v in self.allowed.values()})

    def entry(self, spdx: str) -> dict[str, Any] | None:
        key = spdx.strip().lower()
        return self.allowed.get(key) or self.forbidden.get(key)


_lock = threading.Lock()
_blacklist: Blacklist | None = None
_licenses: LicensePolicy | None = None


def _read_yaml(path: str) -> dict[str, Any]:
    file = Path(path)
    if not file.exists():
        raise FileNotFoundError(path)
    data = yaml.safe_load(file.read_text("utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Файл {path} должен содержать YAML-объект")
    return data


def load_blacklist(path: str | None = None) -> Blacklist:
    path = path or get_settings().blacklist_file
    try:
        data = _read_yaml(path)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        log.warning("blacklist не загружен: %s", exc, extra={"path": path})
        return Blacklist(rules=[], loaded_at=utcnow(), path=path, error=str(exc))

    rules: list[BlacklistRule] = []
    for raw in data.get("rules") or []:
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        rules.append(
            BlacklistRule(
                manager=(raw.get("manager") or None),
                name=str(raw["name"]).strip(),
                versions=str(raw.get("versions", "*")),
                reason=str(raw.get("reason") or "Пакет запрещён правилами blacklist"),
                added_by=raw.get("added_by"),
                added_at=str(raw["added_at"]) if raw.get("added_at") else None,
            )
        )
    log.info("blacklist загружен", extra={"path": path, "rules": len(rules)})
    return Blacklist(rules=rules, loaded_at=utcnow(), path=path)


def load_license_policy(path: str | None = None) -> LicensePolicy:
    path = path or get_settings().allowed_licenses_file
    try:
        data = _read_yaml(path)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        log.warning("справочник лицензий не загружен: %s", exc, extra={"path": path})
        return LicensePolicy(loaded_at=utcnow(), path=path, error=str(exc))

    def collect(section: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for raw in data.get(section) or []:
            if isinstance(raw, str):
                raw = {"spdx_id": raw}
            spdx = str(raw.get("spdx_id") or raw.get("id") or "").strip()
            if not spdx:
                continue
            out[spdx.lower()] = {
                "spdx_id": spdx,
                "name": raw.get("name"),
                "url": raw.get("url"),
                "notes": raw.get("notes"),
                "allowed": section == "allowed",
            }
        return out

    policy = LicensePolicy(
        allowed=collect("allowed"), forbidden=collect("forbidden"), loaded_at=utcnow(), path=path
    )
    log.info(
        "справочник лицензий загружен",
        extra={"path": path, "allowed": len(policy.allowed), "forbidden": len(policy.forbidden)},
    )
    return policy


def get_blacklist() -> Blacklist:
    global _blacklist
    with _lock:
        if _blacklist is None:
            _blacklist = load_blacklist()
        return _blacklist


def get_license_policy() -> LicensePolicy:
    global _licenses
    with _lock:
        if _licenses is None:
            _licenses = load_license_policy()
        return _licenses


def reload_policies() -> dict[str, Any]:
    """Перечитывает файлы конфигурации. Вызывается при старте и из admin/reload."""
    global _blacklist, _licenses
    with _lock:
        _blacklist = load_blacklist()
        _licenses = load_license_policy()
        return {
            "blacklist": {
                "path": _blacklist.path,
                "rules": len(_blacklist.rules),
                "error": _blacklist.error,
                "loaded_at": _blacklist.loaded_at.isoformat() if _blacklist.loaded_at else None,
            },
            "licenses": {
                "path": _licenses.path,
                "allowed": len(_licenses.allowed),
                "forbidden": len(_licenses.forbidden),
                "error": _licenses.error,
                "loaded_at": _licenses.loaded_at.isoformat() if _licenses.loaded_at else None,
            },
        }


def set_policies(blacklist: Blacklist | None = None, licenses: LicensePolicy | None = None) -> None:
    """Подмена политик (тесты)."""
    global _blacklist, _licenses
    with _lock:
        if blacklist is not None:
            _blacklist = blacklist
        if licenses is not None:
            _licenses = licenses
