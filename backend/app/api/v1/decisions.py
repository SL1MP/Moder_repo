"""Ручные решения и очереди ролей: DevSecOps, юристы, карантин, отзыв."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, require_roles
from app.core.errors import ForbiddenError, NotFoundError, ValidationError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.enums import STATUS_TITLES
from app.db.models import LicenseClaim, PackageVersion, PipelineStep, RequestItem, User
from app.db.session import get_db
from app.schemas import (
    LicenseClaimIn,
    LicenseClaimOut,
    LicenseDecisionIn,
    QuarantineReleaseIn,
    QueueItemOut,
    RequestItemOut,
    SecurityDecisionIn,
)
from app.services import decisions, license_snapshot, requests_service

log = get_logger(__name__)
router = APIRouter(tags=["Решения"])

SNAPSHOT_LIMIT = 200_000


def _item(session: Session, item_id: int) -> RequestItem:
    item = session.get(RequestItem, item_id)
    if item is None:
        raise NotFoundError(f"Пакет заявки #{item_id} не найден")
    return item


def _item_payload(session: Session, item: RequestItem) -> RequestItemOut:
    payload = requests_service.request_payload(session, item.request)
    for entry in payload["packages"]:
        if entry["id"] == item.id:
            return RequestItemOut(**entry)
    raise NotFoundError(f"Пакет заявки #{item.id} не найден в заявке")


# --------------------------------------------------------------------------- очереди
@router.get(
    "/queue/security",
    response_model=list[QueueItemOut],
    summary="Очередь DevSecOps (сортировка по времени ожидания)",
)
def queue_security(
    session: Session = Depends(get_db),
    _user: User = Depends(require_roles("devsecops")),
) -> list[QueueItemOut]:
    return _queue(
        session,
        ["awaiting_security", "quarantined"],
        steps=["vuln_scan", "banner_scan", "sast_scan", "quarantine"],
    )


@router.get("/queue/legal", response_model=list[QueueItemOut], summary="Очередь юристов")
def queue_legal(
    session: Session = Depends(get_db),
    _user: User = Depends(require_roles("legal")),
) -> list[QueueItemOut]:
    return _queue(session, ["awaiting_legal", "license_claimed"], steps=["license"])


# Пакет, по которому уже вынесен окончательный вердикт, ни в одной очереди не нужен.
_FINISHED = ("approved", "rejected", "blacklisted", "revoked", "failed")


def _queue(
    session: Session, statuses: list[str], *, steps: list[str] | None = None
) -> list[QueueItemOut]:
    """Пакеты, ждущие решения роли.

    Отбор идёт не только по статусу пакета. Согласования параллельны, а статус у
    пакета один: если лицензия ждёт юриста, а уязвимости — DevSecOps, статусом
    станет более блокирующий `awaiting_security`, и в очереди юристов пакет по
    статусу не нашёлся бы. Поэтому вторым условием берутся сами шаги: шаг с
    результатом `warn` или `fail` означает непогашенное решение своей роли.
    """
    condition = RequestItem.status.in_(statuses)
    if steps:
        by_step = (
            select(PipelineStep.request_item_id)
            .where(
                PipelineStep.step_code.in_(steps),
                PipelineStep.result.in_(("warn", "fail")),
            )
            .scalar_subquery()
        )
        condition = or_(
            condition,
            and_(RequestItem.id.in_(by_step), RequestItem.status.not_in(_FINISHED)),
        )

    rows = session.execute(
        select(RequestItem)
        .where(condition)
        .order_by(RequestItem.waiting_since.asc().nullslast(), RequestItem.id.asc())
    ).scalars().all()

    now = utcnow()
    out: list[QueueItemOut] = []
    for item in rows:
        version = item.package_version
        claim = (
            session.execute(
                select(LicenseClaim)
                .where(
                    LicenseClaim.package_version_id == version.id,
                    LicenseClaim.status == "pending",
                )
                .order_by(LicenseClaim.id.desc())
            )
            .scalars()
            .first()
        )
        waiting_hours = None
        if item.waiting_since:
            waiting = item.waiting_since
            if waiting.tzinfo is None:
                waiting = waiting.replace(tzinfo=now.tzinfo)
            waiting_hours = round((now - waiting).total_seconds() / 3600, 1)
        out.append(
            QueueItemOut(
                item_id=item.id,
                request_id=item.request_id,
                manager=version.package.manager,
                name=item.requested_name,
                version=item.requested_version,
                status=item.status,
                status_title=STATUS_TITLES.get(item.status, item.status),
                current_step=item.current_step,
                blocked_reason=item.blocked_reason,
                waiting_since=item.waiting_since,
                waiting_hours=waiting_hours,
                author=item.request.author.username if item.request.author else None,
                license_spdx=version.license_spdx,
                max_vuln_score=version.max_vuln_score,
                license_claim_id=claim.id if claim else None,
            )
        )
    return out


# --------------------------------------------------------------------------- карантин
@router.post(
    "/items/{item_id}/quarantine/release",
    response_model=RequestItemOut,
    summary="Снять карантин досрочно (DevSecOps)",
)
def release_quarantine(
    item_id: int,
    payload: QuarantineReleaseIn,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("devsecops")),
) -> RequestItemOut:
    item = _item(session, item_id)
    decisions.release_quarantine(
        session, item, actor=user, source="ui", comment=payload.comment, early=True
    )
    session.commit()
    session.expire_all()
    return _item_payload(session, _item(session, item_id))


# --------------------------------------------------------------------------- уязвимости
@router.post(
    "/items/{item_id}/security-decision",
    response_model=RequestItemOut,
    summary="Решение DevSecOps по уязвимостям",
)
def security_decision(
    item_id: int,
    payload: SecurityDecisionIn,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("devsecops")),
) -> RequestItemOut:
    item = _item(session, item_id)
    decisions.decide_security(
        session, item, approve=payload.approve, actor=user, comment=payload.comment, source="ui"
    )
    session.commit()
    session.expire_all()
    return _item_payload(session, _item(session, item_id))


# --------------------------------------------------------------------------- лицензии
@router.post(
    "/items/{item_id}/license-claim",
    response_model=LicenseClaimOut,
    summary="Заявить лицензию (разработчик)",
)
def claim_license(
    request: Request,
    item_id: int,
    payload: LicenseClaimIn,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> LicenseClaimOut:
    item = _item(session, item_id)
    if not (user.has_role("admin", "devsecops", "legal") or item.request.author_id == user.id):
        raise ForbiddenError("Заявить лицензию может автор заявки, юрист, DevSecOps или администратор")

    snapshot = _fetch_license_snapshot(payload.url)
    claim = decisions.claim_license(
        session,
        item,
        url=payload.url,
        spdx_id=payload.spdx_id,
        comment=payload.comment,
        actor=user,
        source="ui",
        snapshot_text=snapshot,
    )
    session.commit()
    return _claim_payload(session, claim)


def _fetch_license_snapshot(url: str) -> str:
    """Проверка доступности ссылки без авторизации + читаемый снапшот текста.

    Ссылку берут из адресной строки браузера, то есть это страница просмотра
    файла в репозитории. Она отдаёт HTML-документ целиком, и раньше он
    сохранялся как есть — юрист видел разметку и скрипты вместо текста
    лицензии. Поэтому ссылка сначала переводится на сырой файл, а если ответ
    всё равно оказался HTML, из него вынимается текст.
    """
    if not url.lower().startswith(("http://", "https://")):
        raise ValidationError("Ссылка на лицензию должна начинаться с http:// или https://")

    target = license_snapshot.raw_url(url)
    with client() as http:
        resp = request_with_retries("license-url", lambda: http.get(target), retries=1)
        if resp.status_code >= 400 and target != url:
            # Догадка про «сырой» адрес не сработала — пробуем исходную ссылку.
            resp = request_with_retries("license-url", lambda: http.get(url), retries=1)
    if resp.status_code >= 400:
        raise ValidationError(
            f"Ссылка недоступна без авторизации (ответ {resp.status_code}). "
            "Приложите публично доступный URL.",
            status=resp.status_code,
        )

    text = license_snapshot.clean_snapshot(
        resp.text,
        content_type=resp.headers.get("content-type", ""),
        limit=SNAPSHOT_LIMIT,
    )
    if not text.strip():
        raise ValidationError("По ссылке пустой ответ — приложите страницу с текстом лицензии")
    return text


@router.get(
    "/license-claims", response_model=list[LicenseClaimOut], summary="Заявления лицензий"
)
def list_license_claims(
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    claim_status: str | None = Query(default="pending", alias="status"),
) -> list[LicenseClaimOut]:
    stmt = select(LicenseClaim).order_by(LicenseClaim.id.desc())
    if claim_status:
        stmt = stmt.where(LicenseClaim.status == claim_status)
    claims = list(session.execute(stmt).scalars())
    if not user.has_role("admin", "legal", "devsecops"):
        claims = [c for c in claims if c.claimed_by_id == user.id]
    return [_claim_payload(session, c) for c in claims]


@router.get("/license-claims/{claim_id}", response_model=LicenseClaimOut, summary="Заявление лицензии")
def get_license_claim(
    claim_id: int,
    session: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> LicenseClaimOut:
    claim = session.get(LicenseClaim, claim_id)
    if claim is None:
        raise NotFoundError(f"Заявление лицензии #{claim_id} не найдено")
    if not user.has_role("admin", "legal", "devsecops") and claim.claimed_by_id != user.id:
        raise ForbiddenError("Заявление доступно его автору, юристам, DevSecOps и администратору")
    return _claim_payload(session, claim)


@router.post(
    "/license-claims/{claim_id}/decision",
    response_model=LicenseClaimOut,
    summary="Решение юриста по лицензии",
)
def decide_license(
    claim_id: int,
    payload: LicenseDecisionIn,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("legal")),
) -> LicenseClaimOut:
    claim = session.get(LicenseClaim, claim_id)
    if claim is None:
        raise NotFoundError(f"Заявление лицензии #{claim_id} не найдено")
    decisions.decide_license(
        session, claim, approve=payload.approve, actor=user, comment=payload.comment, source="ui"
    )
    session.commit()
    session.expire_all()
    claim = session.get(LicenseClaim, claim_id)
    return _claim_payload(session, claim)


def _claim_payload(session: Session, claim: LicenseClaim) -> LicenseClaimOut:
    version = claim.package_version
    return LicenseClaimOut(
        id=claim.id,
        package_version_id=claim.package_version_id,
        request_item_id=claim.request_item_id,
        package=version.package.display_name,
        version=version.raw_version,
        manager=version.package.manager,
        url=claim.url,
        spdx_id=claim.spdx_id,
        comment=claim.comment,
        status=claim.status,
        snapshot_text=(claim.snapshot_text or "")[:20000] or None,
        snapshot_fetched_at=claim.snapshot_fetched_at,
        claimed_by=claim.claimed_by.username if claim.claimed_by else None,
        decided_by=claim.decided_by.username if claim.decided_by else None,
        decided_at=claim.decided_at,
        decision_comment=claim.decision_comment,
        created_at=claim.created_at,
        suggested_license=decisions.suggested_license(session, version),
    )


# --------------------------------------------------------------------------- отзыв
@router.post("/packages/{version_id}/revoke", summary="Отозвать пакет (DevSecOps/admin)")
def revoke_package(
    request: Request,
    version_id: int,
    payload: SecurityDecisionIn,
    session: Session = Depends(get_db),
    user: User = Depends(require_roles("devsecops")),
) -> dict[str, object]:
    version = session.get(PackageVersion, version_id)
    if version is None:
        raise NotFoundError(f"Версия пакета #{version_id} не найдена")
    if not (payload.comment or "").strip():
        raise ValidationError("Причина отзыва обязательна")
    decisions.revoke_version(
        session, version, reason=payload.comment or "", actor=user, source="ui"
    )
    log.info("пакет отозван", extra={"version_id": version_id, "ip": client_ip(request)})
    session.commit()
    return {"package_version_id": version_id, "status": "revoked", "reason": payload.comment}
