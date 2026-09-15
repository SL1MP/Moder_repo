"""Интерфейс плагина пакетного менеджера.

Каждый менеджер (`pypi`, `npm`, `go`, `nuget`) реализует один и тот же контракт:
нормализация имени и версии, валидация формата записи, парсеры файлов
зависимостей, клиент реестра и правила публикации в артефактори.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.errors import InvalidPackageFormat
from app.managers.versioning import OSV_ECOSYSTEMS, get_comparator


@dataclass(frozen=True)
class PackageRef:
    """Разобранная ссылка на пакет конкретной версии."""

    manager: str
    name: str  # нормализованное имя (для уникальности и поиска)
    display_name: str  # как записал разработчик
    version: str  # нормализованная версия
    raw_version: str
    dependency_kind: str = "direct"

    @property
    def entry(self) -> str:
        return f"{self.display_name}@{self.raw_version}"


@dataclass
class ParsedEntry:
    """Результат разбора одной строки/записи: либо ref, либо ошибка формата."""

    raw: str
    ref: PackageRef | None = None
    error: str | None = None
    expected_format: str | None = None


@dataclass
class RegistryMetadata:
    """Метаданные версии из реестра пакетного менеджера."""

    name: str
    version: str
    published_at: datetime | None = None
    license_spdx: str | None = None
    license_raw: str | None = None
    artifact_url: str | None = None
    artifact_filename: str | None = None
    checksum: str | None = None
    checksum_algo: str | None = None
    size_bytes: int | None = None
    yanked: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class PackageManagerPlugin(ABC):
    code: str
    title: str
    entry_format: str
    dependency_files: tuple[str, ...] = ()
    # Файлы, в которых прямые и транзитивные зависимости неразличимы: формат
    # не хранит этот признак. Их записи считаются прямыми (иначе фильтр
    # транзитивных выбросил бы весь файл), а пользователь предупреждается.
    indeterminate_kind_files: tuple[str, ...] = ()

    # ------------------------------------------------------------------ нормализация
    @abstractmethod
    def normalize_name(self, name: str) -> str: ...

    def normalize_version(self, version: str) -> str:
        return version.strip()

    def display_name(self, name: str) -> str:
        return name.strip()

    # ------------------------------------------------------------------ формат записи
    @abstractmethod
    def split_entry(self, entry: str) -> tuple[str, str]:
        """Разбивает строку записи на (имя, версия). Бросает InvalidPackageFormat."""

    def parse_entry(self, entry: str, *, dependency_kind: str = "direct") -> PackageRef:
        name, version = self.split_entry(entry)
        return self.make_ref(name, version, dependency_kind=dependency_kind)

    def make_ref(self, name: str, version: str, *, dependency_kind: str = "direct") -> PackageRef:
        name, version = name.strip(), version.strip()
        if not name:
            raise InvalidPackageFormat(
                f"Не указано имя пакета. Ожидаемый формат: {self.entry_format}",
                expected_format=self.entry_format,
            )
        if not version:
            raise InvalidPackageFormat(
                f"Не указана версия пакета «{name}». Ожидаемый формат: {self.entry_format}",
                expected_format=self.entry_format,
            )
        self.validate_name(name)
        self.validate_version(version)
        return PackageRef(
            manager=self.code,
            name=self.normalize_name(name),
            display_name=self.display_name(name),
            version=self.normalize_version(version),
            raw_version=version,
            dependency_kind=dependency_kind,
        )

    def validate_name(self, name: str) -> None:
        if len(name) > 512:
            raise InvalidPackageFormat("Имя пакета длиннее 512 символов")

    def validate_version(self, version: str) -> None:
        if len(version) > 128:
            raise InvalidPackageFormat("Версия длиннее 128 символов")

    def try_parse_entry(self, entry: str, *, dependency_kind: str = "direct") -> ParsedEntry:
        try:
            return ParsedEntry(raw=entry, ref=self.parse_entry(entry, dependency_kind=dependency_kind))
        except InvalidPackageFormat as exc:
            return ParsedEntry(raw=entry, error=exc.message, expected_format=self.entry_format)

    # ------------------------------------------------------------------ версии
    def compare_versions(self, a: str, b: str) -> int:
        return get_comparator(self.code)(a, b)

    @property
    def osv_ecosystem(self) -> str:
        return OSV_ECOSYSTEMS[self.code]

    # ------------------------------------------------------------------ файлы зависимостей
    def supports_file(self, filename: str) -> bool:
        from fnmatch import fnmatch

        base = filename.rsplit("/", 1)[-1]
        return any(fnmatch(base, pattern) for pattern in self.dependency_files)

    @abstractmethod
    def parse_dependency_file(self, filename: str, content: bytes) -> list[ParsedEntry]:
        """Разбирает файл зависимостей, различая прямые и транзитивные записи."""

    # ------------------------------------------------------------------ реестр
    @abstractmethod
    def fetch_metadata(self, ref: PackageRef) -> RegistryMetadata:
        """Метаданные версии: дата публикации, лицензия, URL артефакта и хеш."""

    # ------------------------------------------------------------------ публикация
    @abstractmethod
    def publish_target(self, ref: PackageRef, filename: str) -> dict[str, str]:
        """Параметры публикации в артефактори (repo/path/format) для этого менеджера."""

    @abstractmethod
    def install_command(self, ref: PackageRef, base_url: str, repo: str) -> str:
        """Готовая команда установки из внутреннего репозитория (для UI)."""
