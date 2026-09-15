"""Создание заявок на модерацию — раздел 6 задания.

Оба способа заведения (перечисление пакетов и файл с зависимостями) сводятся к
одному разбору: нормализация → дедупликация по базе → создание заявки →
асинхронный запуск конвейера.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, LimitExceeded, NotFoundError
from app.core.logging import get_logger
from app.db.enums import STATUS_TITLES, STEP_TITLES
from app.db.models import ModerationRequest, RequestItem, User
from app.managers.base import PackageRef, ParsedEntry
from app.managers.registry import get_plugin, parse_entries, parse_file
from app.pipeline.blockers import pending_blockers
from app.pipeline.runner import ensure_steps, recompute_request_status, step_snapshot
from app.services import audit, packages

log = get_logger(__name__)

TRANSITIVE_WARNING = (
    "Проверяется и публикуется только сам заявленный пакет. Транзитивные зависимости "
    "автоматически не подтягиваются — если они нужны, заведите их отдельно."
)


@dataclass
class ParsedPackage:
    """Пакет из заявки с пометкой о дальнейшей судьбе."""

    raw: str
    state: str  # new | already_in_base | invalid_format
    ref: PackageRef | None = None
    message: str | None = None
    expected_format: str | None = None
    existing_version_id: int | None = None
    existing_status: str | None = None
    install_command: str | None = None
    dependency_kind: str = "direct"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "raw": self.raw,
            "state": self.state,
            "name": self.ref.display_name if self.ref else None,
            "version": self.ref.raw_version if self.ref else None,
            "dependency_kind": self.dependency_kind,
            "message": self.message,
        }
        if self.state == "invalid_format":
            payload["expected_format"] = self.expected_format
        if self.state == "already_in_base":
            payload["package_version_id"] = self.existing_version_id
            payload["status"] = self.existing_status
            payload["link"] = f"/api/v1/packages/{self.existing_version_id}"
            payload["install_command"] = self.install_command
        return payload


@dataclass
class ParseResult:
    manager: str
    packages: list[ParsedPackage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def new(self) -> list[ParsedPackage]:
        return [p for p in self.packages if p.state == "new"]


def _kind_is_indeterminate(plugin, filename: str) -> bool:
    """Файл, в котором прямые и транзитивные зависимости неразличимы."""
    from fnmatch import fnmatch
    from pathlib import PurePosixPath

    base = PurePosixPath(filename).name.lower()
    return any(fnmatch(base, pattern) for pattern in getattr(plugin, "indeterminate_kind_files", ()))


def parse_payload(
    session: Session,
    *,
    manager: str,
    entries: list[str] | None = None,
    structured: list[dict[str, str]] | None = None,
    filename: str | None = None,
    content: bytes | None = None,
    include_transitive: bool = False,
) -> ParseResult:
    """Разбирает вход обоих способов и помечает каждый пакет: new / already_in_base / invalid_format."""
    s = get_settings()
    plugin = get_plugin(manager)
    result = ParseResult(manager=plugin.code)

    parsed: list[ParsedEntry] = []
    if content is not None:
        if len(content) > s.max_upload_size_bytes:
            raise LimitExceeded(
                f"Файл больше допустимого размера {s.max_upload_size_bytes} байт",
                size=len(content),
                limit=s.max_upload_size_bytes,
            )
        parsed = parse_file(manager, filename or "", content)
        if _kind_is_indeterminate(plugin, filename or ""):
            # go.sum и подобные: признака прямой зависимости в файле нет, все
            # записи считаются прямыми. Иначе фильтр транзитивных выбросил бы
            # весь файл и заявка получилась бы пустой.
            result.warnings.append(
                f"Файл «{filename}» перечисляет весь граф модулей: и прямые зависимости, "
                "и транзитивные — формат их не различает. Приняты все записи; "
                "лишние удалите из заявки вручную."
            )
        has_transitive = any(e.ref and e.ref.dependency_kind == "transitive" for e in parsed)
        if has_transitive:
            result.warnings.append(TRANSITIVE_WARNING)
            if not include_transitive:
                skipped = sum(1 for e in parsed if e.ref and e.ref.dependency_kind == "transitive")
                parsed = [e for e in parsed if not (e.ref and e.ref.dependency_kind == "transitive")]
                result.warnings.append(
                    f"Транзитивных зависимостей в файле: {skipped}. Они пропущены "
                    "(include_transitive=false)."
                )
    else:
        if structured:
            for row in structured:
                name = str(row.get("name", "")).strip()
                version = str(row.get("version", "")).strip()
                raw = f"{name} {version}".strip()
                try:
                    ref = plugin.make_ref(name, version)
                except Exception as exc:  # noqa: BLE001 - InvalidPackageFormat и производные
                    parsed.append(
                        ParsedEntry(
                            raw=raw,
                            error=getattr(exc, "message", str(exc)),
                            expected_format=plugin.entry_format,
                        )
                    )
                else:
                    parsed.append(ParsedEntry(raw=raw, ref=ref))
        if entries:
            parsed.extend(parse_entries(manager, entries))

    if not parsed:
        raise NotFoundError("В запросе не найдено ни одного пакета для модерации")
    if len(parsed) > s.max_packages_per_request:
        raise LimitExceeded(
            f"В заявке {len(parsed)} пакетов, максимум {s.max_packages_per_request}",
            count=len(parsed),
            limit=s.max_packages_per_request,
        )

    seen: set[tuple[str, str]] = set()
    for entry in parsed:
        if entry.ref is None:
            result.packages.append(
                ParsedPackage(
                    raw=entry.raw,
                    state="invalid_format",
                    message=entry.error,
                    expected_format=entry.expected_format or plugin.entry_format,
                )
            )
            continue
        key = (entry.ref.name, entry.ref.version)
        if key in seen:
            continue
        seen.add(key)

        existing = packages.find_version(session, entry.ref)
        if existing is not None and existing.status == "approved":
            # Уже одобренные в заявку не попадают — отдаём ссылку и команду установки.
            result.packages.append(
                ParsedPackage(
                    raw=entry.raw,
                    state="already_in_base",
                    ref=entry.ref,
                    existing_version_id=existing.id,
                    existing_status=existing.status,
                    install_command=packages.install_command(session, existing),
                    dependency_kind=entry.ref.dependency_kind,
                    message=f"{entry.ref.display_name} {entry.ref.raw_version} уже одобрен — "
                    "заявка по нему не требуется.",
                )
            )
            continue
        if existing is not None and existing.status in ("blacklisted", "revoked", "rejected"):
            result.packages.append(
                ParsedPackage(
                    raw=entry.raw,
                    state="already_in_base",
                    ref=entry.ref,
                    existing_version_id=existing.id,
                    existing_status=existing.status,
                    dependency_kind=entry.ref.dependency_kind,
                    message=(
                        f"{entry.ref.display_name} {entry.ref.raw_version}: "
                        f"{STATUS_TITLES.get(existing.status, existing.status)}. "
                        f"{existing.status_reason or ''}".strip()
                    ),
                )
            )
            continue

        result.packages.append(
            ParsedPackage(
                raw=entry.raw,
                state="new",
                ref=entry.ref,
                dependency_kind=entry.ref.dependency_kind,
            )
        )
    return result


def find_by_idempotency_key(session: Session, key: str) -> ModerationRequest | None:
    if not key:
        return None
    return session.execute(
        select(ModerationRequest).where(ModerationRequest.idempotency_key == key)
    ).scalars().first()


def create_request(
    session: Session,
    *,
    author: User,
    parse_result: ParseResult,
    reason: str | None,
    source: str = "api",
    idempotency_key: str | None = None,
    origin_file: str | None = None,
    include_transitive: bool = False,
    actor_role: str | None = None,
) -> ModerationRequest:
    """Создаёт заявку из разобранного списка. Конвейер запускается вызывающим кодом."""
    if idempotency_key:
        existing = find_by_idempotency_key(session, idempotency_key)
        if existing is not None:
            raise ConflictError(
                "Заявка с таким Idempotency-Key уже создана", request_id=existing.id
            )

    request = ModerationRequest(
        author_id=author.id,
        author_role=actor_role,
        manager=parse_result.manager,
        reason=reason,
        status="pending",
        source=source,
        idempotency_key=idempotency_key,
        origin_file=origin_file,
        include_transitive=include_transitive,
        warnings=parse_result.warnings or None,
    )
    session.add(request)
    session.flush()

    for parsed in parse_result.new:
        assert parsed.ref is not None
        version, _created = packages.get_or_create_version(session, parsed.ref)
        item = RequestItem(
            request_id=request.id,
            package_version_id=version.id,
            requested_name=parsed.ref.display_name,
            requested_version=parsed.ref.raw_version,
            dependency_kind=parsed.dependency_kind,
            status="queued",
        )
        session.add(item)
        session.flush()
        ensure_steps(session, item)

    audit.record(
        session,
        action="request_created",
        entity_type="moderation_request",
        entity_id=request.id,
        actor=author,
        actor_role=actor_role,
        new_value={
            "manager": request.manager,
            "packages": [p.raw for p in parse_result.new],
            "already_in_base": [p.raw for p in parse_result.packages if p.state == "already_in_base"],
            "invalid": [p.raw for p in parse_result.packages if p.state == "invalid_format"],
            "reason": reason,
            "source": source,
        },
        source=source if source in ("api", "ui", "cli") else "api",
    )
    recompute_request_status(session, request)
    session.flush()
    return request


def get_request(session: Session, request_id: int) -> ModerationRequest:
    request = session.get(ModerationRequest, request_id)
    if request is None:
        raise NotFoundError(f"Заявка #{request_id} не найдена")
    return request


def request_payload(
    session: Session, request: ModerationRequest, *, include_steps: bool = True
) -> dict[str, Any]:
    """Агрегат заявки + по каждому пакету: текущий шаг, результат, причина, что делать дальше."""
    items: list[dict[str, Any]] = []
    for item in request.items:
        version = item.package_version
        payload: dict[str, Any] = {
            "id": item.id,
            "package_version_id": version.id,
            "name": item.requested_name,
            "version": item.requested_version,
            "dependency_kind": item.dependency_kind,
            "status": item.status,
            "status_title": STATUS_TITLES.get(item.status, item.status),
            # Какие решения ролей ещё не получены. Статус у пакета один, а ждать
            # он может двух сразу — интерфейс показывает блоки решений по этому
            # списку, иначе более блокирующий статус скрыл бы блок второй роли.
            "pending": pending_blockers(item),
            "current_step": item.current_step,
            "current_step_title": STEP_TITLES.get(item.current_step or "", None),
            "blocked_reason": item.blocked_reason,
            "next_action": item.next_action,
            "waiting_since": item.waiting_since,
            "finished_at": item.finished_at,
            "license_spdx": version.license_spdx,
            "quarantine_until": version.quarantine_until,
            "max_vuln_score": version.max_vuln_score,
            "vulnerabilities": [
                {
                    "id": v.external_id,
                    "score": v.score,
                    "cvss_vector": v.cvss_vector,
                    "severity": v.severity,
                    "url": v.url,
                    "summary": v.summary,
                    "fixed_versions": v.fixed_versions,
                }
                for v in sorted(version.vulnerabilities, key=lambda v: -v.score)
            ],
            # Находки сканеров содержимого: политические баннеры и SAST.
            "code_findings": [
                {
                    "scanner": f.scanner,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "file": f.file_path,
                    "line": f.line,
                    "matched": f.matched,
                }
                for f in sorted(version.code_findings, key=lambda f: (f.scanner, f.file_path or ""))
            ],
        }
        if version.status == "approved":
            payload["install_command"] = packages.install_command(session, version)
        if include_steps:
            payload["steps"] = step_snapshot(item)
        items.append(payload)

    approved = bool(items) and all(i["status"] == "approved" for i in items)
    return {
        "request_id": request.id,
        "manager": request.manager,
        "status": request.status,
        "status_title": STATUS_TITLES.get(request.status, request.status),
        "approved": approved,
        "author": request.author.username if request.author else None,
        "author_role": request.author_role,
        "reason": request.reason,
        "source": request.source,
        "origin_file": request.origin_file,
        "include_transitive": request.include_transitive,
        "warnings": request.warnings or [],
        "created_at": request.created_at,
        "updated_at": request.updated_at,
        "summary": _summary(items),
        "packages": items,
    }


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "total": len(items),
        "by_status": counts,
        "approved": counts.get("approved", 0),
        "awaiting_security": counts.get("awaiting_security", 0),
        "awaiting_legal": counts.get("awaiting_legal", 0) + counts.get("license_claimed", 0),
        "quarantined": counts.get("quarantined", 0),
        "rejected": counts.get("rejected", 0)
        + counts.get("blacklisted", 0)
        + counts.get("revoked", 0),
        "failed": counts.get("failed", 0),
    }


def is_settled(request: ModerationRequest) -> bool:
    """Заявка достигла финального состояния (для `wait=true`)."""
    return all(
        item.status not in ("queued", "running")
        for item in request.items
    )
