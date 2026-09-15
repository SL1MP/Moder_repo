"""Настройки (только чтение), перечитывание конфигурации, аудит-лог."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.vuln_index import get_vuln_index
from app.api.deps import client_ip, get_current_user, require_roles
from app.core.config import get_settings, settings_catalog
from app.db.models import AuditLog, User, VulnIndexVersion
from app.db.session import get_db
from app.schemas import AuditOut, SettingOut
from app.services import audit, watchdog
from app.services.audit import SOURCE_TITLES
from app.services.policies import get_blacklist, get_license_policy, reload_policies
from app.services.worker_health import worker_status

router = APIRouter(tags=["Администрирование"])


@router.get(
    "/settings",
    response_model=list[SettingOut],
    summary="Действующие настройки (только чтение, с именем переменной)",
)
def read_settings(_user: User = Depends(get_current_user)) -> list[SettingOut]:
    return [SettingOut(**row) for row in settings_catalog()]


@router.get("/settings/policies", summary="Состояние blacklist и справочника лицензий")
def read_policies(_user: User = Depends(get_current_user)) -> dict[str, object]:
    blacklist = get_blacklist()
    licenses = get_license_policy()
    index = get_vuln_index()
    info = index.current_version()
    s = get_settings()
    return {
        "blacklist": {
            "path": blacklist.path,
            "rules": [r.as_dict() for r in blacklist.rules],
            "loaded_at": blacklist.loaded_at,
            "error": blacklist.error,
        },
        "licenses": {
            "path": licenses.path,
            "allowed": sorted(licenses.allowed.values(), key=lambda x: x["spdx_id"]),
            "forbidden": sorted(licenses.forbidden.values(), key=lambda x: x["spdx_id"]),
            "loaded_at": licenses.loaded_at,
            "error": licenses.error,
        },
        "vuln_index": {
            "source": index.source,
            "version": info.version if info else None,
            "published_at": info.published_at if info else None,
            "record_count": info.record_count if info else None,
            "age_days": round(info.age_days(), 2) if info and info.age_days() is not None else None,
            "max_staleness_days": s.osv_max_staleness_days,
            "stale": index.is_stale(s.osv_max_staleness_days),
        },
    }


@router.get("/system/status", summary="Обработка очереди: worker и сторож")
def read_system_status(
    session: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict[str, object]:
    """Кто разбирает очередь и не завис ли в ней кто-нибудь.

    Экран «Настройка» показывает это, чтобы «пакет вечно проверяется» не
    приходилось диагностировать по логам контейнеров.
    """
    s = get_settings()
    status = worker_status()
    stuck = watchdog.find_stuck(session, include_running=not status.alive)
    return {
        "worker": status.to_dict(),
        "watchdog": {
            "enabled": s.pipeline_watchdog_enabled,
            "interval_seconds": s.pipeline_watchdog_interval_seconds,
            "stuck_after_seconds": s.pipeline_stuck_after_seconds,
        },
        "queue": {
            "stuck_items": len(stuck),
            "stuck_item_ids": stuck[:50],
        },
    }


@router.post(
    "/admin/queue-sweep",
    summary="Немедленно прогнать зависшие в очереди пакеты (роль admin)",
)
def sweep_queue(
    request: Request,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("admin")),
) -> dict[str, object]:
    """Ручной запуск сторожа — то же, что `moderctl run-pending`, но из UI/API."""
    result = watchdog.sweep()
    audit.record(
        session,
        action="queue_swept",
        entity_type="system",
        entity_id=0,
        actor=user,
        new_value=result,
        source="api",
        ip=client_ip(request),
    )
    session.commit()
    return result


@router.post("/admin/reload", summary="Перечитать blacklist и справочник лицензий")
def reload_configuration(
    request: Request,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("admin")),
) -> dict[str, object]:
    result = reload_policies()
    audit.record(
        session,
        action="config_reloaded",
        entity_type="configuration",
        actor=user,
        new_value=result,
        source="ui",
        ip=client_ip(request),
    )
    session.commit()
    return result


@router.get("/admin/audit", response_model=list[AuditOut], summary="Аудит-лог (роль admin)")
def read_audit(
    session: Session = Depends(get_db),
    _user: User = Depends(require_roles("admin")),
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> list[AuditOut]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == str(entity_id))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_name == actor)
    stmt = stmt.limit(limit).offset(offset)
    return [
        AuditOut(
            id=row.id,
            actor_name=row.actor_name,
            actor_role=row.actor_role,
            action=row.action,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            old_value=row.old_value,
            new_value=row.new_value,
            source=row.source,
            source_title=SOURCE_TITLES.get(row.source, row.source),
            comment=row.comment,
            ip=row.ip,
            created_at=row.created_at,
        )
        for row in session.execute(stmt).scalars()
    ]


@router.get("/admin/osv-versions", summary="Загруженные версии снапшота OSV")
def osv_versions(
    session: Session = Depends(get_db),
    _user: User = Depends(require_roles("devsecops")),
) -> list[dict[str, object]]:
    rows = session.execute(
        select(VulnIndexVersion).order_by(VulnIndexVersion.id.desc()).limit(50)
    ).scalars()
    return [
        {
            "id": r.id,
            "version": r.version,
            "source": r.source,
            "checksum": r.checksum,
            "published_at": r.published_at,
            "downloaded_at": r.downloaded_at,
            "record_count": r.record_count,
            "is_active": r.is_active,
        }
        for r in rows
    ]


@router.post("/admin/osv-sync", summary="Запустить синхронизацию снапшота OSV")
def trigger_osv_sync(
    request: Request,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("devsecops")),
    force: bool = Query(default=False),
) -> dict[str, object]:
    from app.tasks.celery_app import publish
    from app.tasks.scheduled import SYNC_OSV_SNAPSHOT, sync_osv_snapshot

    audit.record(
        session,
        action="osv_sync_triggered",
        entity_type="vuln_index_version",
        actor=user,
        new_value={"force": force},
        source="ui",
        ip=client_ip(request),
    )
    session.commit()
    try:
        # Эндпоинт синхронный, значит выполняется в пуле потоков FastAPI —
        # публиковать можно только через приложение явно (см. publish).
        task = publish(SYNC_OSV_SNAPSHOT, force)
        return {"queued": True, "task_id": getattr(task, "id", None)}
    except Exception:  # noqa: BLE001 - без брокера выполняем синхронно
        return {"queued": False, "result": sync_osv_snapshot(force)}
