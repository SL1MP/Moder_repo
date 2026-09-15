"""Регламентные задачи Celery beat: карантин, снапшот OSV, перепроверка, очистка MinIO."""

from __future__ import annotations

from datetime import timedelta

from celery import shared_task
from sqlalchemy import select

from app.adapters.artifact_store import get_artifact_store
from app.adapters.object_storage import get_object_storage
from app.adapters.vuln_index import OsvSnapshotIndex, get_vuln_index
from app.core.config import get_settings
from app.core.logging import get_logger, new_request_id, request_id_var
from app.core.metrics import osv_index_age_days
from app.db.base import utcnow
from app.db.models import Artifact, Package, PackageVersion, RequestItem, VulnIndexVersion
from app.db.session import session_scope
from app.services import audit, decisions

# См. комментарий в app/tasks/pipeline_tasks.py.
from app.tasks.celery_app import celery_app, publish  # noqa: F401,E402

log = get_logger(__name__)

SYNC_OSV_SNAPSHOT = "app.tasks.scheduled.sync_osv_snapshot"
RESCAN_APPROVED = "app.tasks.scheduled.rescan_approved"


@shared_task(name="app.tasks.scheduled.release_quarantine")
def release_quarantine() -> dict[str, int]:
    """Снимает карантин у версий, у которых срок вышел, и возобновляет конвейер с шага 3."""
    request_id_var.set(new_request_id())
    released = 0
    with session_scope() as session:
        rows = session.execute(
            select(RequestItem)
            .join(PackageVersion, RequestItem.package_version_id == PackageVersion.id)
            .where(
                RequestItem.status == "quarantined",
                PackageVersion.quarantine_until.is_not(None),
                PackageVersion.quarantine_until <= utcnow(),
            )
        ).scalars().all()
        item_ids = [item.id for item in rows]

    for item_id in item_ids:
        with session_scope() as session:
            item = session.get(RequestItem, item_id)
            if item is None or item.status != "quarantined":
                continue
            try:
                decisions.release_quarantine(
                    session, item, actor=None, source="task", early=False, comment="Срок карантина истёк"
                )
                released += 1
            except Exception:  # noqa: BLE001 - одна ошибка не должна ронять весь прогон
                log.exception("не удалось снять карантин", extra={"item_id": item_id})
    log.info("карантин снят", extra={"released": released})
    return {"released": released}


@shared_task(name="app.tasks.scheduled.sync_osv_snapshot")
def sync_osv_snapshot(force: bool = False) -> dict[str, object]:
    """Загружает снапшот OSV из артефактори, если появился новее загруженного."""
    request_id_var.set(new_request_id())
    s = get_settings()
    if s.osv_source != "snapshot":
        log.info("OSV_SOURCE=api — синхронизация снапшота не требуется")
        return {"synced": False, "reason": "osv_source_api"}

    index = OsvSnapshotIndex()
    info = index.sync(force=force)
    if info is None:
        current = index.current_version()
        if current:
            _report_age(current)
        return {"synced": False, "version": current.version if current else None}

    with session_scope() as session:
        row = session.execute(
            select(VulnIndexVersion).where(VulnIndexVersion.version == info.version)
        ).scalars().first()
        if row is None:
            row = VulnIndexVersion(version=info.version, source=info.source)
            session.add(row)
        row.checksum = info.checksum
        row.remote_path = info.remote_path
        row.local_path = info.local_path
        row.published_at = info.published_at
        row.downloaded_at = utcnow()
        row.record_count = info.record_count
        row.is_active = True
        session.flush()
        session.query(VulnIndexVersion).filter(VulnIndexVersion.id != row.id).update(
            {"is_active": False}
        )
        audit.record(
            session,
            action="osv_snapshot_synced",
            entity_type="vuln_index_version",
            entity_id=row.id,
            new_value={"version": info.version, "records": info.record_count},
            source="task",
        )
        version_id = row.id
    _report_age(info)
    # Новый снапшот -> перепроверка ранее одобренных пакетов.
    try:
        publish(RESCAN_APPROVED, version_id)
    except Exception as exc:  # noqa: BLE001 - без брокера выполняем синхронно
        log.warning("брокер недоступен, перепроверка выполняется синхронно: %s", exc)
        rescan_approved(version_id)
    return {"synced": True, "version": info.version, "records": info.record_count}


def _report_age(info) -> None:
    age = info.age_days()
    if age is not None:
        osv_index_age_days.set(age)


@shared_task(name="app.tasks.scheduled.rescan_approved")
def rescan_approved(index_version_id: int | None = None) -> dict[str, int]:
    """Перепроверяет одобренные пакеты после загрузки нового снапшота.

    Артефакт берётся из артефактори, а не заново из внешнего реестра.
    """
    request_id_var.set(new_request_id())
    s = get_settings()
    index = get_vuln_index()
    checked = revoked = 0

    with session_scope() as session:
        version_ids = list(
            session.execute(
                select(PackageVersion.id).where(PackageVersion.status == "approved")
            ).scalars()
        )

    for version_id in version_ids:
        with session_scope() as session:
            version = session.get(PackageVersion, version_id)
            if version is None or version.status != "approved":
                continue
            package: Package = version.package
            # Что по этой версии уже было известно на момент одобрения: отзываем только
            # по НОВОЙ уязвимости, иначе каждый новый снапшот молча отменял бы принятое
            # решение DevSecOps по уже разобранной CVE.
            known_ids = {v.external_id for v in version.vulnerabilities}
            try:
                findings = index.query(package.manager, package.name, version.version)
            except Exception:  # noqa: BLE001
                log.exception("перепроверка не выполнена", extra={"package_version_id": version_id})
                continue
            checked += 1
            worst = max((f.score for f in findings), default=0.0)
            version.max_vuln_score = worst
            version.vuln_index_version_id = index_version_id or version.vuln_index_version_id

            breaching = [f for f in findings if f.score > s.vuln_max_score]
            fresh = [f for f in breaching if f.external_id not in known_ids]
            if not fresh:
                if breaching:
                    log.info(
                        "уязвимость выше порога уже была учтена при одобрении — пакет не отзывается",
                        extra={
                            "package_version_id": version_id,
                            "ids": [f.external_id for f in breaching],
                        },
                    )
                continue

            top = max(fresh, key=lambda f: f.score)
            # Скачиваем артефакт из артефактори — для фиксации факта, что проверка велась
            # по опубликованной копии, а не по внешнему реестру.
            _verify_published_copy(version)
            decisions.revoke_version(
                session,
                version,
                reason=(
                    f"Новая уязвимость {top.external_id} (балл {top.score:g} > порога "
                    f"{s.vuln_max_score:g}) обнаружена после обновления базы OSV."
                ),
                source="task",
            )
            revoked += 1

    log.info("перепроверка одобренных завершена", extra={"checked": checked, "revoked": revoked})
    return {"checked": checked, "revoked": revoked}


def _verify_published_copy(version: PackageVersion) -> None:
    store = get_artifact_store()
    for artifact in version.artifacts:
        if not artifact.nexus_url:
            continue
        try:
            store.download(artifact.nexus_url)
        except Exception as exc:  # noqa: BLE001 - отсутствие копии не отменяет отзыв
            log.warning(
                "опубликованная копия недоступна: %s", exc, extra={"url": artifact.nexus_url}
            )
        return


@shared_task(name="app.tasks.scheduled.cleanup_orphan_objects")
def cleanup_orphan_objects() -> dict[str, int]:
    """Удаляет из MinIO объекты, зависшие дольше `S3_ORPHAN_TTL_HOURS`."""
    request_id_var.set(new_request_id())
    s = get_settings()
    cutoff = utcnow() - timedelta(hours=s.s3_orphan_ttl_hours)
    storage = get_object_storage()
    removed = 0

    with session_scope() as session:
        rows = session.execute(
            select(Artifact).where(
                Artifact.s3_key.is_not(None),
                Artifact.s3_deleted_at.is_(None),
                Artifact.s3_uploaded_at.is_not(None),
                Artifact.s3_uploaded_at < cutoff,
            )
        ).scalars().all()
        for artifact in rows:
            if storage.delete(artifact.s3_key or ""):
                removed += 1
            artifact.s3_deleted_at = utcnow()
            if artifact.status != "published":
                artifact.status = "purged"
        if rows:
            audit.record(
                session,
                action="s3_orphans_cleaned",
                entity_type="artifact",
                new_value={"removed": removed, "ttl_hours": s.s3_orphan_ttl_hours},
                source="task",
            )

    # Объекты без записи в БД (сбои до flush) тоже подчищаем.
    try:
        known = set()
        with session_scope() as session:
            known = {
                key
                for (key,) in session.execute(
                    select(Artifact.s3_key).where(Artifact.s3_deleted_at.is_(None))
                ).all()
                if key
            }
        for obj in storage.list_objects():
            if obj.key in known:
                continue
            if obj.last_modified and obj.last_modified.timestamp() > cutoff.timestamp():
                continue  # объект свежий: заявка может быть ещё в работе
            storage.delete(obj.key)
            removed += 1
    except Exception:  # noqa: BLE001 - недоступность хранилища не должна ронять задачу
        log.exception("не удалось перечислить объекты временного хранилища")

    log.info("очистка временного хранилища завершена", extra={"removed": removed})
    return {"removed": removed}
