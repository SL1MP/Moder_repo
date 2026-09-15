from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RawDependency:
    """Запись из файла зависимостей до нормализации плагином."""

    name: str
    version: str
    kind: str = "direct"  # direct | transitive
    note: str | None = None


__all__ = ["RawDependency"]
