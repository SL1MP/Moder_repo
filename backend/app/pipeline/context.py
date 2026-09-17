from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.adapters.notifier import Notifier, get_notifier
from app.adapters.vuln_index import VulnerabilityIndex, get_vuln_index
from app.core.config import Settings, get_settings
from app.db.models import ModerationRequest, Package, PackageVersion, RequestItem, User
from app.managers.base import PackageManagerPlugin, PackageRef
from app.managers.registry import get_plugin


@dataclass
class StepOutcome:
    """Результат шага конвейера."""

    result: str  # pass | info | warn | fail
    message: str
    details: dict[str, Any] | None = None
    stop: bool = False
    item_status: str | None = None
    version_status: str | None = None
    next_action: str | None = None  # блок «Что делать» для разработчика
    notify_roles: list[str] = field(default_factory=list)
    notify_event: str | None = None
    terminal: bool = False  # шаг завершил обработку успешно (пакет одобрен)
    # Шаг не пройден и требует решения роли, но конвейер продолжается: следующие
    # шаги выполняются, чтобы вторая роль увидела пакет в своей очереди сразу, а
    # не после решения первой. Публикация не состоится, пока блокировка не снята
    # (см. PublishStep и pending_blockers в app/pipeline/runner.py).
    defer: bool = False

    @classmethod
    def ok(cls, message: str, **kwargs: Any) -> StepOutcome:
        return cls(result="pass", message=message, **kwargs)

    @classmethod
    def warn(cls, message: str, **kwargs: Any) -> StepOutcome:
        kwargs.setdefault("stop", True)
        return cls(result="warn", message=message, **kwargs)

    @classmethod
    def fail(cls, message: str, **kwargs: Any) -> StepOutcome:
        kwargs.setdefault("stop", True)
        return cls(result="fail", message=message, **kwargs)

    @classmethod
    def pending(cls, message: str, **kwargs: Any) -> StepOutcome:
        """Нужно решение роли, но конвейер идёт дальше — согласования параллельны."""
        kwargs.setdefault("stop", False)
        kwargs.setdefault("defer", True)
        return cls(result="warn", message=message, **kwargs)

    @classmethod
    def info(cls, message: str, **kwargs: Any) -> StepOutcome:
        """Шаг выполнен, публикацию не блокирует, но сказать по нему есть что.

        Отдельный результат, а не `pass`: «пройден» рядом с четырьмя находками
        читается как «чисто». И не `warn`: warn означает непогашенное
        согласование (см. blockers.py), а информационный шаг ничьего решения не
        ждёт. Таким шагом сделан SAST — находки нужны для отчёта, а не для
        запрета.
        """
        return cls(result="info", message=message, **kwargs)


@dataclass
class PipelineContext:
    session: Session
    item: RequestItem
    version: PackageVersion
    package: Package
    request: ModerationRequest
    settings: Settings = field(default_factory=get_settings)
    actor: User | None = None  # None = фоновая задача
    source: str = "task"
    cache: dict[str, Any] = field(default_factory=dict)

    @property
    def plugin(self) -> PackageManagerPlugin:
        return get_plugin(self.package.manager)

    @property
    def notifier(self) -> Notifier:
        return get_notifier()

    @property
    def vuln_index(self) -> VulnerabilityIndex:
        return get_vuln_index()

    @property
    def ref(self) -> PackageRef:
        return PackageRef(
            manager=self.package.manager,
            name=self.package.name,
            display_name=self.package.display_name,
            version=self.version.version,
            raw_version=self.version.raw_version,
            dependency_kind=self.item.dependency_kind,
        )

    @property
    def label(self) -> str:
        return f"{self.package.display_name} {self.version.raw_version}"
