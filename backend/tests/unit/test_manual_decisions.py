"""Возобновление конвейера после ручных решений и снятия карантина."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.errors import ConflictError, ValidationError
from app.db.models import LicenseClaim, Notification
from app.pipeline.runner import run_pipeline
from app.services import decisions
from tests.factories import make_request, steps_by_code

pytestmark = pytest.mark.usefixtures("policies", "store", "storage", "vuln_index", "notifier")


# --------------------------------------------------------------------------- карантин
def test_quarantine_release_resumes_from_license(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=2)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.status == "quarantined"

    decisions.release_quarantine(session, item, actor=users["devsecops"], source="ui")

    steps = steps_by_code(item)
    # Снятие карантина гасит блокировку шага: пока она непогашена, публикация
    # не состоится (шаг повторно не выполняется — дата публикации не изменилась).
    assert steps["quarantine"].result == "pass"
    assert steps["license"].result == "pass"
    assert steps["publish"].result == "pass"
    assert item.status == "approved"


def test_quarantine_release_requires_quarantined_status(session, users, fake_metadata):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    with pytest.raises(ConflictError):
        decisions.release_quarantine(session, item, actor=users["devsecops"])


def test_quarantine_release_notifies_author(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=1)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    decisions.release_quarantine(session, item, actor=users["devsecops"])
    session.commit()

    events = session.query(Notification).filter(Notification.user_id == users["developer"].id).all()
    assert any(n.event == "quarantine_released" for n in events)


# --------------------------------------------------------------------------- уязвимости
def test_security_approval_redownloads_and_publishes(
    session, users, fake_metadata, vuln_index, finding_factory, store
):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.status == "awaiting_security"
    assert item.package_version.artifacts[0].s3_deleted_at is not None

    # DevSecOps разрешает: конвейер возобновляется с шага скачивания.
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [])
    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Уязвимость не применима"
    )

    assert item.status == "approved"
    assert steps_by_code(item)["download"].result == "pass"
    assert store.published


def test_security_rejection_marks_rejected(session, users, fake_metadata, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)

    decisions.decide_security(
        session, item, approve=False, actor=users["devsecops"], comment="Критичная RCE"
    )

    assert item.status == "rejected"
    assert item.package_version.status == "rejected"
    assert item.request.status == "rejected"


def test_security_rejection_requires_comment(session, users, fake_metadata, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    with pytest.raises(ValidationError, match="комментарий обязателен"):
        decisions.decide_security(session, item, approve=False, actor=users["devsecops"])


# --------------------------------------------------------------------------- лицензии
def _stop_on_license(session, users, fake_metadata):
    fake_metadata["license_spdx"] = None
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.status == "awaiting_legal"
    return item


def test_license_claim_sets_claimed_status(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    claim = decisions.claim_license(
        session,
        item,
        url="https://example.org/LICENSE",
        spdx_id="MIT",
        comment="Файл лицензии в корне репозитория",
        actor=users["developer"],
        snapshot_text="MIT License ...",
    )
    assert claim.status == "pending"
    assert item.status == "license_claimed"
    assert item.request.status == "awaiting_legal"


def test_license_claim_notifies_legal(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    decisions.claim_license(
        session,
        item,
        url="https://example.org/LICENSE",
        spdx_id="MIT",
        comment=None,
        actor=users["developer"],
    )
    session.commit()
    events = session.query(Notification).filter(Notification.user_id == users["legal"].id).all()
    assert any(n.event == "license_claimed" for n in events)


def test_license_approval_resumes_from_download(session, users, fake_metadata, store):
    item = _stop_on_license(session, users, fake_metadata)
    claim = decisions.claim_license(
        session,
        item,
        url="https://example.org/LICENSE",
        spdx_id="MIT",
        comment=None,
        actor=users["developer"],
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"], comment="Ок")

    assert claim.status == "approved"
    assert item.status == "approved"
    assert item.package_version.license_spdx == "MIT"
    assert item.package_version.license_source == "claim"
    assert steps_by_code(item)["download"].result == "pass"
    assert store.published


def test_license_confirmed_is_suggested_for_other_version(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT", comment=None, actor=users["developer"]
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"])
    session.commit()

    # Другая версия того же пакета получает подсказку с явной пометкой.
    _, other = make_request(session, users["developer"], name="somepkg", version="1.1.0")
    suggestion = decisions.suggested_license(session, other.package_version)
    assert suggestion["spdx_id"] == "MIT"
    assert suggestion["confirmed_for_version"] == "1.0.0"
    assert "другой версии" in suggestion["note"]


def test_license_rejection_stops_and_requires_comment(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id=None, comment=None, actor=users["developer"]
    )
    with pytest.raises(ValidationError):
        decisions.decide_license(session, claim, approve=False, actor=users["legal"])

    decisions.decide_license(
        session, claim, approve=False, actor=users["legal"], comment="Лицензия несовместима"
    )
    assert claim.status == "rejected"
    assert item.status == "rejected"
    assert item.package_version.status == "rejected"


def test_second_decision_on_claim_conflicts(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT", comment=None, actor=users["developer"]
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"])
    with pytest.raises(ConflictError):
        decisions.decide_license(session, claim, approve=True, actor=users["legal"])


def test_license_step_uses_approved_claim_on_rerun(session, users, fake_metadata):
    item = _stop_on_license(session, users, fake_metadata)
    claim = LicenseClaim(
        package_version_id=item.package_version_id,
        request_item_id=item.id,
        claimed_by_id=users["developer"].id,
        url="https://example.org/L",
        spdx_id="Apache-2.0",
        status="approved",
        decided_by_id=users["legal"].id,
        decided_at=datetime.now(UTC),
    )
    session.add(claim)
    session.commit()

    run_pipeline(session, item, from_step="license")
    step = steps_by_code(item)["license"]
    assert step.result == "pass"
    assert "подтверждена юристами" in step.message


# --------------------------------------------------------------------------- отзыв
def test_revoke_unpublishes_and_notifies(session, users, fake_metadata, store):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()
    assert store.published

    decisions.revoke_version(
        session, item.package_version, reason="Новая критичная CVE", actor=users["devsecops"], source="ui"
    )
    session.commit()

    assert item.package_version.status == "revoked"
    assert not store.published
    assert item.status == "revoked"
    events = session.query(Notification).filter(Notification.user_id == users["developer"].id).all()
    assert any(n.event == "package_revoked" for n in events)


def test_license_claim_rejects_spdx_outside_reference(session, users, fake_metadata):
    """SPDX можно только выбрать из справочника, вписать произвольный — нельзя.

    Ограничение стоит и в интерфейсе (выпадающий список), но проверка нужна на
    сервере: API вызывают и мимо UI, а произвольная строка тихо ломает
    автоматическую сверку лицензии на следующем прогоне конвейера.
    """
    item = _stop_on_license(session, users, fake_metadata)

    with pytest.raises(ValidationError, match="отсутствует в справочнике"):
        decisions.claim_license(
            session,
            item,
            url="https://example.org/LICENSE",
            spdx_id="СВОЯ-ЛИЦЕНЗИЯ-1.0",
            comment=None,
            actor=users["developer"],
        )


def test_license_claim_without_spdx_is_allowed(session, users, fake_metadata):
    """Идентификатор необязателен: юрист может определить лицензию по ссылке."""
    item = _stop_on_license(session, users, fake_metadata)

    claim = decisions.claim_license(
        session,
        item,
        url="https://example.org/LICENSE",
        spdx_id=None,
        comment=None,
        actor=users["developer"],
    )

    assert claim.status == "pending"
    assert claim.spdx_id is None
