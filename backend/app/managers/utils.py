from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from app.managers.parsers import RawDependency

if TYPE_CHECKING:  # pragma: no cover
    from app.managers.base import PackageManagerPlugin, ParsedEntry


def parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text[: len(fmt) + 2], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def raw_deps_to_entries(
    plugin: PackageManagerPlugin, raw: list[RawDependency]
) -> list[ParsedEntry]:
    """Превращает записи парсера в ParsedEntry, сохраняя ошибки формата.

    Имя и версия здесь уже разделены парсером файла, поэтому строку записи
    заново не собираем — вызываем `make_ref` напрямую.
    """
    from app.core.errors import InvalidPackageFormat
    from app.managers.base import ParsedEntry

    entries: list[ParsedEntry] = []
    for dep in raw:
        label = f"{dep.name} {dep.version}".strip()
        if not dep.version:
            entries.append(
                ParsedEntry(
                    raw=label,
                    error=dep.note or f"Для «{dep.name}» не указана точная версия",
                    expected_format=plugin.entry_format,
                )
            )
            continue
        try:
            ref = plugin.make_ref(dep.name, dep.version, dependency_kind=dep.kind)
        except InvalidPackageFormat as exc:
            entries.append(ParsedEntry(raw=label, error=exc.message, expected_format=plugin.entry_format))
            continue
        entries.append(ParsedEntry(raw=label, ref=ref))
    return entries
