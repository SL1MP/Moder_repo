"""Реестр плагинов пакетных менеджеров."""

from __future__ import annotations

from app.core.errors import InvalidPackageFormat, UnknownManagerError
from app.managers.base import PackageManagerPlugin, ParsedEntry
from app.managers.golang import GoPlugin
from app.managers.npm import NpmPlugin
from app.managers.nuget import NugetPlugin
from app.managers.pypi import PypiPlugin

_PLUGINS: dict[str, PackageManagerPlugin] = {
    p.code: p
    for p in (PypiPlugin(), NpmPlugin(), GoPlugin(), NugetPlugin())
}


def get_plugin(manager: str) -> PackageManagerPlugin:
    plugin = _PLUGINS.get((manager or "").strip().lower())
    if plugin is None:
        raise UnknownManagerError(
            f"Неизвестный пакетный менеджер «{manager}». Поддерживаются: "
            + ", ".join(sorted(_PLUGINS))
        )
    return plugin


def all_plugins() -> list[PackageManagerPlugin]:
    return list(_PLUGINS.values())


def manager_codes() -> list[str]:
    return list(_PLUGINS)


def detect_manager_by_file(filename: str) -> str | None:
    """Определяет менеджер по имени файла зависимостей (для UI-подсказки)."""
    for plugin in _PLUGINS.values():
        if plugin.supports_file(filename):
            return plugin.code
    return None


def parse_entries(manager: str, entries: list[str]) -> list[ParsedEntry]:
    plugin = get_plugin(manager)
    return [plugin.try_parse_entry(e) for e in entries]


def parse_file(manager: str, filename: str, content: bytes) -> list[ParsedEntry]:
    plugin = get_plugin(manager)
    if not plugin.supports_file(filename):
        raise InvalidPackageFormat(
            f"Файл «{filename}» не поддерживается менеджером {manager}. Поддерживаются: "
            + ", ".join(plugin.dependency_files)
        )
    return plugin.parse_dependency_file(filename, content)


__all__ = [
    "all_plugins",
    "detect_manager_by_file",
    "get_plugin",
    "manager_codes",
    "parse_entries",
    "parse_file",
]
