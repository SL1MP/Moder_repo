"""Работа с базой пакетов: поиск, дедупликация, получение/создание версий."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.enums import PENDING_VERSION_STATUSES, STATUS_TITLES
from app.db.models import Package, PackageVersion, RequestItem
from app.managers.base import PackageRef
from app.managers.registry import get_plugin

APPROVED_STATUSES = ("approved",)


def find_version(session: Session, ref: PackageRef) -> PackageVersion | None:
    stmt = (
        select(PackageVersion)
        .join(Package)
        .where(
            Package.manager == ref.manager,
            Package.name == ref.name,
            PackageVersion.version == ref.version,
        )
    )
    return session.execute(stmt).scalars().first()


def get_or_create_version(session: Session, ref: PackageRef) -> tuple[PackageVersion, bool]:
    """Возвращает версию пакета и признак «создана только что»."""
    package = session.execute(
        select(Package).where(Package.manager == ref.manager, Package.name == ref.name)
    ).scalars().first()
    if package is None:
        package = Package(manager=ref.manager, name=ref.name, display_name=ref.display_name)
        session.add(package)
        session.flush()

    version = session.execute(
        select(PackageVersion).where(
            PackageVersion.package_id == package.id, PackageVersion.version == ref.version
        )
    ).scalars().first()
    if version is not None:
        return version, False

    version = PackageVersion(
        package_id=package.id, version=ref.version, raw_version=ref.raw_version, status="new"
    )
    session.add(version)
    session.flush()
    return version, True


def install_command(session: Session, version: PackageVersion) -> str:
    s = get_settings()
    plugin = get_plugin(version.package.manager)
    ref = version_ref(version)
    return plugin.install_command(ref, s.artifact_base_url, s.artifact_repo(version.package.manager))


def version_ref(version: PackageVersion) -> PackageRef:
    return PackageRef(
        manager=version.package.manager,
        name=version.package.name,
        display_name=version.package.display_name,
        version=version.version,
        raw_version=version.raw_version,
    )


def search_versions(
    session: Session,
    *,
    query: str | None = None,
    manager: str | None = None,
    version: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[PackageVersion], int]:
    """Поиск по базе пакетов: имя, версия, менеджер, статус."""
    stmt = select(PackageVersion).join(Package)
    count_stmt = select(func.count()).select_from(PackageVersion).join(Package)
    conditions = []
    if query:
        pattern = f"%{query.strip().lower()}%"
        conditions.append(
            or_(func.lower(Package.name).like(pattern), func.lower(Package.display_name).like(pattern))
        )
    if manager:
        conditions.append(Package.manager == manager)
    if version:
        conditions.append(PackageVersion.version.like(f"{version.strip()}%"))
    if status:
        conditions.append(PackageVersion.status == status)
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.execute(count_stmt).scalar_one()
    stmt = stmt.order_by(Package.name, PackageVersion.id.desc()).limit(limit).offset(offset)
    return list(session.execute(stmt).scalars().all()), int(total)


def check_state(session: Session, version: PackageVersion) -> dict[str, Any]:
    """Что разработчику делать с найденной в базе версией.

    Наличие записи само по себе ничего не значит: строка создаётся в момент
    заведения заявки, до всех проверок. Поэтому отдаём не «найдено/не найдено», а
    состояние по существу: можно ставить, идёт проверка или проверку не прошёл.
    """
    status = version.status
    payload: dict[str, Any] = {
        "status": status,
        "status_title": STATUS_TITLES.get(status, status),
        "package_version_id": version.id,
        "link": f"/api/v1/packages/{version.id}",
        "status_reason": version.status_reason,
    }

    if status == "approved":
        payload["state"] = "approved"
        payload["message"] = "Одобрен — можно ставить из внутреннего репозитория."
        payload["install_command"] = install_command(session, version)
        return payload

    if status in PENDING_VERSION_STATUSES:
        # Заявка уже есть — подсказываем её номер, чтобы не заводили вторую.
        item = session.execute(
            select(RequestItem)
            .where(RequestItem.package_version_id == version.id)
            .order_by(RequestItem.id.desc())
        ).scalars().first()
        payload["state"] = "in_progress"
        payload["request_id"] = item.request_id if item else None
        payload["current_step"] = item.current_step if item else None
        payload["next_action"] = item.next_action if item else None
        where = f" (заявка #{item.request_id})" if item else ""
        payload["message"] = (
            f"Ставить нельзя: пакет ещё не прошёл модерацию — {payload['status_title'].lower()}"
            f"{where}. Повторную заявку заводить не нужно."
        )
        return payload

    payload["state"] = "blocked"
    reason = (version.status_reason or "").strip()
    if reason and reason[-1] not in ".!?":
        reason += "."  # причина приходит из разных мест, точку в конце не гарантируем
    payload["message"] = " ".join(
        part
        for part in (
            f"Ставить нельзя: {payload['status_title'].lower()}.",
            reason,
            "Подберите другую версию или замену.",
        )
        if part
    )
    return payload


def version_summary(session: Session, version: PackageVersion) -> dict[str, Any]:
    package = version.package
    payload: dict[str, Any] = {
        "id": version.id,
        "manager": package.manager,
        "name": package.display_name,
        "normalized_name": package.name,
        "version": version.raw_version,
        "status": version.status,
        "license_spdx": version.license_spdx,
        "license_source": version.license_source,
        "published_at": version.published_at,
        "quarantine_until": version.quarantine_until,
        "approved_at": version.approved_at,
        "max_vuln_score": version.max_vuln_score,
        "status_reason": version.status_reason,
        "vulnerabilities": [
            {
                "id": v.external_id,
                "score": v.score,
                "cvss_vector": v.cvss_vector,
                "severity": v.severity,
                "url": v.url,
                "summary": v.summary,
                "fixed_versions": v.fixed_versions,
                "affected_ranges": v.affected_ranges,
                "index_version_id": v.vuln_index_version_id,
            }
            for v in sorted(version.vulnerabilities, key=lambda v: -v.score)
        ],
        "artifacts": [
            {
                "filename": a.filename,
                "nexus_url": a.nexus_url,
                "sha256": a.sha256,
                "size_bytes": a.size_bytes,
                "s3_key": a.s3_key,
                "s3_deleted_at": a.s3_deleted_at,
                "status": a.status,
            }
            for a in version.artifacts
        ],
    }
    if version.status == "approved":
        payload["install_command"] = install_command(session, version)
    return payload
