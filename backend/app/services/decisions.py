"""Ручные решения: карантин, уязвимости, лицензии, отзыв пакета."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.artifact_store import get_artifact_store
from app.adapters.notifier import EVENT_TITLES, Event, NotificationMessage, get_notifier
from app.core.errors import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import LicenseClaim, ModerationRequest, PackageVersion, RequestItem, User
from app.pipeline.blockers import clear_blocker, is_blocked_by, status_from_blockers
from app.pipeline.runner import recompute_request_status, resume_item
from app.services import audit, packages
from app.services.policies import get_license_policy

log = get_logger(__name__)


def _notify_author(
    session: Session, item: RequestItem, event: str, body: str, extra_users: list[int] | None = None
) -> None:
    label = f"{item.requested_name} {item.requested_version}"
    message = NotificationMessage(
        event=event,
        title=f"{EVENT_TITLES.get(event, 'Событие')}: {label}",
        body=body,
        request_id=item.request_id,
        request_item_id=item.id,
        payload={"package": label, "status": item.status},
    )
    recipients = [item.request.author_id, *(extra_users or [])]
    get_notifier().notify_users(session, recipients, message)


def siblings_awaiting(
    session: Session, item: RequestItem, statuses: tuple[str, ...]
) -> list[RequestItem]:
    """Пакеты той же версии в других заявках, ждущие того же решения.

    Решение роли выносится по версии пакета, а не по заявке: подтверждённая
    лицензия, разрешение DevSecOps и снятие карантина пишутся в
    `PackageVersion` и относятся ко всем, кто заказал эту версию. Раньше
    возобновлялся только тот `RequestItem`, из которого пришло решение, и
    одинаковый пакет в чужой заявке висел заблокированным навсегда, хотя
    вердикт для него уже был вынесен.
    """
    return list(
        session.execute(
            select(RequestItem)
            .where(
                RequestItem.package_version_id == item.package_version_id,
                RequestItem.id != item.id,
                RequestItem.status.in_(statuses),
            )
            .order_by(RequestItem.id)
        ).scalars()
    )


def _apply_to_siblings(
    session: Session,
    item: RequestItem,
    statuses: tuple[str, ...],
    *,
    actor: User | None,
    source: str,
    from_step: str,
    note: str,
    clear_step: str | tuple[str, ...] | None = None,
) -> int:
    """Возобновляет конвейер у тех же пакетов в других заявках."""
    affected = siblings_awaiting(session, item, statuses)
    for sibling in affected:
        for code in (clear_step,) if isinstance(clear_step, str) else (clear_step or ()):
            clear_blocker(session, sibling, code, note)
        _notify_author(session, sibling, Event.DECISION_MADE, note)
        resume_item(session, sibling, actor=actor, source=source, from_step=from_step, note=note)
    if affected:
        log.info(
            "решение применено к тем же пакетам в других заявках",
            extra={"item_id": item.id, "siblings": [s.id for s in affected]},
        )
    return len(affected)


def _reject_siblings(
    session: Session,
    item: RequestItem,
    statuses: tuple[str, ...],
    *,
    comment: str | None,
    next_action: str,
    note: str,
) -> int:
    """Отклонение тоже относится ко всем, кто заказал эту версию."""
    affected = siblings_awaiting(session, item, statuses)
    for sibling in affected:
        sibling.status = "rejected"
        sibling.finished_at = utcnow()
        sibling.waiting_since = None
        sibling.blocked_reason = comment
        sibling.next_action = next_action
        _notify_author(session, sibling, Event.DECISION_MADE, note)
        recompute_request_status(session, sibling.request)
    if affected:
        session.flush()
    return len(affected)


def get_item(session: Session, item_id: int) -> RequestItem:
    item = session.get(RequestItem, item_id)
    if item is None:
        raise NotFoundError(f"Пакет заявки #{item_id} не найден")
    return item


# --------------------------------------------------------------------------- карантин
def release_quarantine(
    session: Session,
    item: RequestItem,
    *,
    actor: User | None,
    source: str = "ui",
    comment: str | None = None,
    early: bool = True,
) -> RequestItem:
    """Снимает карантин: досрочно (DevSecOps) или по истечении срока (фоновая задача)."""
    if item.status != "quarantined":
        raise ConflictError(
            f"Пакет не находится в карантине (текущий статус: {item.status})", status=item.status
        )
    version = item.package_version
    audit.record(
        session,
        action="quarantine_released_early" if early else "quarantine_released",
        entity_type="package_version",
        entity_id=version.id,
        actor=actor,
        old_value={"status": version.status, "quarantine_until": _iso(version.quarantine_until)},
        new_value={"released": True, "early": early},
        source=source if actor else "task",
        comment=comment,
    )
    version.quarantine_until = None
    note = (
        "Карантин снят досрочно решением DevSecOps — проверка продолжена."
        if early
        else "Срок карантина истёк — проверка продолжена автоматически."
    )
    _notify_author(session, item, Event.QUARANTINE_RELEASED, note)
    src = source if actor else "task"
    # Карантин снят с версии пакета — значит, и со всех, кто её заказал.
    _apply_to_siblings(
        session, item, ("quarantined",), actor=actor, source=src, from_step="license",
        note=note, clear_step="quarantine",
    )
    # Шаг карантина повторно не выполняется (дата публикации не изменилась),
    # поэтому блокировку снимаем явно — иначе публикация будет ждать вечно.
    clear_blocker(session, item, "quarantine", note)
    return resume_item(session, item, actor=actor, source=src, from_step="license", note=note)


# --------------------------------------------------------------------------- уязвимости
def decide_security(
    session: Session,
    item: RequestItem,
    *,
    approve: bool,
    actor: User,
    comment: str | None = None,
    source: str = "ui",
) -> RequestItem:
    """Решение DevSecOps по пакету, остановленному на шаге уязвимостей."""
    if item.status != "awaiting_security":
        raise ConflictError(
            f"Пакет не ждёт решения DevSecOps (текущий статус: {item.status})", status=item.status
        )
    if not approve and not (comment or "").strip():
        raise ValidationError("При отклонении комментарий обязателен")

    version = item.package_version
    old = {"status": item.status, "version_status": version.status}
    audit.record(
        session,
        action="security_approved" if approve else "security_rejected",
        entity_type="request_item",
        entity_id=item.id,
        actor=actor,
        old_value=old,
        new_value={"approved": approve},
        source=source,
        comment=comment,
    )
    if approve:
        # Решение фиксируем на версии пакета: иначе возобновлённый конвейер снова
        # упрётся в тот же вердикт шага 5 и вернёт пакет в очередь — решение
        # DevSecOps не имело бы эффекта.
        version.security_override_at = utcnow()
        version.security_override_by_id = actor.id
        version.security_override_comment = comment
        session.flush()

        note = f"DevSecOps разрешил публикацию: {comment or 'без комментария'}. Проверка продолжена."
        _notify_author(session, item, Event.DECISION_MADE, note)
        # Разрешение записано на версии пакета — применяем ко всем заявкам с ней.
        _apply_to_siblings(
            session, item, ("awaiting_security",), actor=actor, source=source,
            from_step="download", note=note, clear_step=("vuln_scan", "banner_scan", "sast_scan"),
        )
        # Разрешение DevSecOps закрывает все его проверки разом: уязвимости,
        # политические баннеры и SAST — по каждой из них решение уже принято.
        for code in ("vuln_scan", "banner_scan", "sast_scan"):
            clear_blocker(session, item, code, note)
        # Артефакт был удалён из MinIO при отклонении на шаге 5 — перекачиваем.
        return resume_item(session, item, actor=actor, source=source, from_step="download", note=note)

    item.status = "rejected"
    item.finished_at = utcnow()
    item.waiting_since = None
    item.blocked_reason = comment
    item.next_action = "Возьмите другую версию пакета или согласуйте замену с DevSecOps."
    version.status = "rejected"
    version.status_reason = comment
    _purge_artifacts(session, version, reason="Отклонён решением DevSecOps")
    _reject_siblings(
        session, item, ("awaiting_security",),
        comment=comment,
        next_action="Возьмите другую версию пакета или согласуйте замену с DevSecOps.",
        note=f"DevSecOps отклонил пакет: {comment}",
    )
    _notify_author(session, item, Event.DECISION_MADE, f"DevSecOps отклонил пакет: {comment}")
    recompute_request_status(session, item.request)
    session.flush()
    return item


# --------------------------------------------------------------------------- лицензии
def claim_license(
    session: Session,
    item: RequestItem,
    *,
    url: str,
    spdx_id: str | None,
    comment: str | None,
    actor: User,
    source: str = "ui",
    snapshot_text: str | None = None,
) -> LicenseClaim:
    """Заявление лицензии разработчиком для пакета, остановленного на шаге 3."""
    # Проверяем блокировку, а не статус: согласования идут параллельно, и пока
    # лицензия у юриста, статусом пакета может быть более блокирующий
    # `awaiting_security` — по нему заявление ошибочно отклонялось бы.
    if not (is_blocked_by(item, "license") or item.status in ("awaiting_legal", "license_claimed")):
        raise ConflictError(
            f"Пакет не ждёт решения по лицензии (текущий статус: {item.status})", status=item.status
        )
    if spdx_id:
        # Только идентификатор из справочника. Ограничение стоит и в интерфейсе
        # (там выпадающий список), но проверка нужна и здесь: API вызывают и
        # мимо UI, а произвольная строка тихо ломает автоматическую сверку
        # лицензии на следующем прогоне конвейера.
        policy = get_license_policy()
        if policy.entry(spdx_id) is None:
            known = ", ".join(policy.known_ids()[:15])
            raise ValidationError(
                f"SPDX-идентификатор «{spdx_id}» отсутствует в справочнике. "
                f"Выберите один из известных: {known}…",
                spdx_id=spdx_id,
            )

    version = item.package_version
    claim = LicenseClaim(
        package_version_id=version.id,
        request_item_id=item.id,
        claimed_by_id=actor.id,
        url=url,
        spdx_id=spdx_id,
        comment=comment,
        status="pending",
        snapshot_text=snapshot_text,
        snapshot_fetched_at=utcnow() if snapshot_text else None,
    )
    session.add(claim)
    session.flush()

    # Не понижаем статус: если пакет ещё и у DevSecOps, это важнее.
    item.status = status_from_blockers(item, "license_claimed")
    if item.status == "awaiting_legal":
        item.status = "license_claimed"
    item.next_action = "Лицензия заявлена, ожидается подтверждение юриста."
    version.status = item.status
    audit.record(
        session,
        action="license_claimed",
        entity_type="license_claim",
        entity_id=claim.id,
        actor=actor,
        new_value={"url": url, "spdx_id": spdx_id, "package_version_id": version.id},
        source=source,
        comment=comment,
    )
    label = f"{item.requested_name} {item.requested_version}"
    get_notifier().notify_roles(
        session,
        ["legal"],
        NotificationMessage(
            event=Event.LICENSE_CLAIMED,
            title=f"{EVENT_TITLES[Event.LICENSE_CLAIMED]}: {label}",
            body=f"{actor.display_name} приложил ссылку на лицензию: {url}",
            request_id=item.request_id,
            request_item_id=item.id,
            payload={"package": label, "url": url, "spdx_id": spdx_id},
        ),
    )
    recompute_request_status(session, item.request)
    session.flush()
    return claim


def decide_license(
    session: Session,
    claim: LicenseClaim,
    *,
    approve: bool,
    actor: User,
    comment: str | None = None,
    source: str = "ui",
) -> LicenseClaim:
    """Решение юриста по заявленной лицензии. Подтверждение возобновляет конвейер с шага 4."""
    if claim.status != "pending":
        raise ConflictError(f"По заявлению лицензии уже принято решение: {claim.status}")
    if not approve and not (comment or "").strip():
        raise ValidationError("При отклонении комментарий обязателен")

    version = claim.package_version
    claim.status = "approved" if approve else "rejected"
    claim.decided_by_id = actor.id
    claim.decided_at = utcnow()
    claim.decision_comment = comment

    audit.record(
        session,
        action="license_approved" if approve else "license_rejected",
        entity_type="license_claim",
        entity_id=claim.id,
        actor=actor,
        old_value={"status": "pending"},
        new_value={"status": claim.status, "spdx_id": claim.spdx_id},
        source=source,
        comment=comment,
    )

    item = session.get(RequestItem, claim.request_item_id) if claim.request_item_id else None
    if approve:
        version.license_spdx = claim.spdx_id or version.license_spdx
        version.license_source = "claim"
        # Подтверждённая лицензия предлагается для других версий этого пакета.
        package = version.package
        package.confirmed_license_spdx = version.license_spdx
        package.confirmed_license_version = version.raw_version
        session.flush()
        note = (
            f"Юрист подтвердил лицензию {version.license_spdx or 'по ссылке'} — "
            "проверка продолжена со шага скачивания."
        )
        if item is not None:
            _notify_author(session, item, Event.DECISION_MADE, note)
            # Лицензия подтверждена для версии пакета: тот же пакет, заказанный
            # в другой заявке, обязан сдвинуться вместе с этим.
            _apply_to_siblings(
                session, item, ("awaiting_legal", "license_claimed"), actor=actor,
                source=source, from_step="download", note=note, clear_step="license",
            )
            # Возобновление идёт с шага скачивания, шаг лицензии повторно не
            # выполняется — снимаем его блокировку явно.
            clear_blocker(session, item, "license", note)
            resume_item(session, item, actor=actor, source=source, from_step="download", note=note)
        else:
            # Заявление не привязано к пакету заявки (импорт, CLI) — разблокируем
            # всех, кто ждёт решения по этой версии.
            waiting = list(
                session.execute(
                    select(RequestItem).where(
                        RequestItem.package_version_id == version.id,
                        RequestItem.status.in_(("awaiting_legal", "license_claimed")),
                    ).order_by(RequestItem.id)
                ).scalars()
            )
            for pending in waiting:
                clear_blocker(session, pending, "license", note)
                _notify_author(session, pending, Event.DECISION_MADE, note)
                resume_item(
                    session, pending, actor=actor, source=source, from_step="download", note=note
                )
        return claim

    if item is not None:
        item.status = "rejected"
        item.finished_at = utcnow()
        item.waiting_since = None
        item.blocked_reason = comment
        item.next_action = "Лицензия не согласована. Подберите пакет с разрешённой лицензией."
        version.status = "rejected"
        version.status_reason = comment
        _purge_artifacts(session, version, reason="Отклонён решением юриста")
        _reject_siblings(
            session, item, ("awaiting_legal", "license_claimed"),
            comment=comment,
            next_action="Лицензия не согласована. Подберите пакет с разрешённой лицензией.",
            note=f"Юрист отклонил лицензию: {comment}",
        )
        _notify_author(session, item, Event.DECISION_MADE, f"Юрист отклонил лицензию: {comment}")
        recompute_request_status(session, item.request)
    else:
        version.status = "rejected"
        version.status_reason = comment
    session.flush()
    return claim


def suggested_license(session: Session, version: PackageVersion) -> dict[str, Any] | None:
    """Подтверждённая ранее лицензия этого пакета — с пометкой, что это другая версия."""
    package = version.package
    if not package.confirmed_license_spdx:
        return None
    return {
        "spdx_id": package.confirmed_license_spdx,
        "confirmed_for_version": package.confirmed_license_version,
        "note": (
            f"Лицензия {package.confirmed_license_spdx} была подтверждена для версии "
            f"{package.confirmed_license_version} — подтверждение относится к другой версии."
        ),
    }


# --------------------------------------------------------------------------- отзыв
def revoke_version(
    session: Session,
    version: PackageVersion,
    *,
    reason: str,
    actor: User | None = None,
    source: str = "task",
    unpublish: bool = True,
) -> PackageVersion:
    """Отзыв пакета: снятие с публикации, статус `revoked`, уведомление авторам заявок."""
    old_status = version.status
    version.status = "revoked"
    version.status_reason = reason
    version.revoked_at = utcnow()

    if unpublish:
        ref = packages.version_ref(version)
        store = get_artifact_store()
        for artifact in version.artifacts:
            if not artifact.nexus_url:
                continue
            try:
                store.delete(ref, artifact.filename)
                artifact.status = "purged"
            except UpstreamError as exc:
                log.warning(
                    "не удалось снять артефакт с публикации: %s",
                    exc.message,
                    extra={"artifact": artifact.filename},
                )

    audit.record(
        session,
        action="package_revoked",
        entity_type="package_version",
        entity_id=version.id,
        actor=actor,
        old_value={"status": old_status},
        new_value={"status": "revoked", "reason": reason},
        source=source,
        comment=reason,
    )

    label = f"{version.package.display_name} {version.raw_version}"
    message = NotificationMessage(
        event=Event.PACKAGE_REVOKED,
        title=f"{EVENT_TITLES[Event.PACKAGE_REVOKED]}: {label}",
        body=reason,
        payload={"package": label, "manager": version.package.manager},
    )
    notifier = get_notifier()
    notifier.notify_roles(session, ["devsecops"], message)

    authors = session.execute(
        select(ModerationRequest.author_id)
        .join(RequestItem, RequestItem.request_id == ModerationRequest.id)
        .where(RequestItem.package_version_id == version.id)
    ).scalars().all()
    notifier.notify_users(session, list(authors), message)

    for item in session.execute(
        select(RequestItem).where(RequestItem.package_version_id == version.id)
    ).scalars():
        if item.status == "approved":
            item.status = "revoked"
            item.blocked_reason = reason
            item.next_action = "Пакет отозван: перейдите на исправленную версию."
            recompute_request_status(session, item.request)
    session.flush()
    return version


def _purge_artifacts(session: Session, version: PackageVersion, *, reason: str) -> None:
    """Удаляет объекты из MinIO при отклонении пакета."""
    from app.adapters.object_storage import get_object_storage

    storage = get_object_storage()
    for artifact in version.artifacts:
        if artifact.s3_key and artifact.s3_deleted_at is None:
            storage.delete(artifact.s3_key)
            artifact.s3_deleted_at = utcnow()
            artifact.status = "purged"
            log.info(
                "объект удалён из временного хранилища",
                extra={"key": artifact.s3_key, "reason": reason},
            )
    session.flush()


def _iso(value) -> str | None:
    return value.isoformat() if value else None
