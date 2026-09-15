"""Регламентные задачи: снятие карантина, перепроверка одобренных, очистка MinIO."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db.base import utcnow
from app.db.models import Notification
from app.pipeline.runner import run_pipeline
from app.tasks.scheduled import cleanup_orphan_objects, release_quarantine, rescan_approved
from tests.factories import make_request, steps_by_code

pytestmark = pytest.mark.usefixtures("policies", "store", "storage", "vuln_index", "notifier")


def test_release_quarantine_resumes_expired(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=2)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.status == "quarantined"

    # Срок карантина «истёк».
    item.package_version.quarantine_until = utcnow() - timedelta(hours=1)
    session.commit()

    result = release_quarantine()
    assert result["released"] == 1

    session.expire_all()
    refreshed = session.get(type(item), item.id)
    assert refreshed.status == "approved"
    assert steps_by_code(refreshed)["publish"].result == "pass"


def test_release_quarantine_skips_not_expired(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=2)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    assert release_quarantine()["released"] == 0
    session.expire_all()
    assert session.get(type(item), item.id).status == "quarantined"


def test_rescan_revokes_on_new_cve(session, users, fake_metadata, vuln_index, finding_factory, store):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()
    assert item.package_version.status == "approved"

    # Новый снапшот принёс критичную уязвимость.
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.9)])
    result = rescan_approved()

    assert result["checked"] >= 1
    assert result["revoked"] == 1
    session.expire_all()
    version = session.get(type(item.package_version), item.package_version_id)
    assert version.status == "revoked"
    assert "после обновления базы OSV" in (version.status_reason or "")
    assert not store.published  # снят с публикации


def test_rescan_keeps_approved_below_threshold(
    session, users, fake_metadata, vuln_index, finding_factory
):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=4.0)])
    assert rescan_approved()["revoked"] == 0
    session.expire_all()
    assert session.get(type(item.package_version), item.package_version_id).status == "approved"


def test_rescan_notifies_author_and_devsecops(
    session, users, fake_metadata, vuln_index, finding_factory
):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.9)])
    rescan_approved()
    session.expire_all()

    for role in ("developer", "devsecops"):
        events = session.query(Notification).filter(Notification.user_id == users[role].id).all()
        assert any(n.event == "package_revoked" for n in events), role


def test_cleanup_removes_stale_objects(session, users, fake_metadata, storage, vuln_index, finding_factory):
    # Заявка застряла на шаге уязвимостей до удаления объекта: имитируем «зависший» артефакт.
    vuln_index.stale = True
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    artifact = item.package_version.artifacts[0]
    assert artifact.s3_deleted_at is None
    assert storage.exists(artifact.s3_key)

    artifact.s3_uploaded_at = utcnow() - timedelta(hours=48)
    session.commit()

    result = cleanup_orphan_objects()
    assert result["removed"] >= 1
    session.expire_all()
    assert not storage.exists(artifact.s3_key)
    assert session.get(type(artifact), artifact.id).s3_deleted_at is not None


def test_cleanup_keeps_fresh_objects(session, users, fake_metadata, storage, vuln_index):
    vuln_index.stale = True
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    artifact = item.package_version.artifacts[0]
    assert cleanup_orphan_objects()["removed"] == 0
    assert storage.exists(artifact.s3_key)


def test_rescan_does_not_revoke_already_known_cve(
    session, users, fake_metadata, vuln_index, finding_factory, store
):
    """Уязвимость, учтённую при одобрении, повторный снапшот не отзывает.

    Иначе каждый новый снапшот молча отменял бы решение DevSecOps «публиковать
    несмотря на эту CVE».
    """
    from app.services import decisions

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.9)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.status == "awaiting_security"

    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Риск принят"
    )
    session.commit()
    assert item.status == "approved"
    assert store.published

    # Новый снапшот приносит ту же самую CVE — отзыва быть не должно.
    result = rescan_approved()
    assert result["revoked"] == 0
    session.expire_all()
    assert session.get(type(item.package_version), item.package_version_id).status == "approved"
    assert store.published


def test_rescan_revokes_on_genuinely_new_cve_after_override(
    session, users, fake_metadata, vuln_index, finding_factory, store
):
    """А вот новая, ранее неизвестная CVE выше порога отзывает пакет и с override."""
    from app.services import decisions

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory("CVE-2024-0001", score=9.9)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Риск принят"
    )
    session.commit()

    vuln_index.set_findings(
        "pypi",
        "somepkg",
        "1.0.0",
        [finding_factory("CVE-2024-0001", score=9.9), finding_factory("CVE-2025-9999", score=9.5)],
    )
    assert rescan_approved()["revoked"] == 1
    session.expire_all()
    version = session.get(type(item.package_version), item.package_version_id)
    assert version.status == "revoked"
    assert "CVE-2025-9999" in (version.status_reason or "")
    assert not store.published
