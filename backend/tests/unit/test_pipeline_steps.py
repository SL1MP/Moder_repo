"""Каждый шаг конвейера отдельно: остановка после fail/warn и пропуск дальнейших шагов."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db.models import Notification
from app.pipeline.runner import run_pipeline
from tests.factories import make_request, steps_by_code

pytestmark = pytest.mark.usefixtures("policies", "store", "storage", "vuln_index", "notifier")


# --------------------------------------------------------------------------- шаг 0
def test_step0_already_approved_stops_pipeline(session, users, fake_metadata):
    _, item = make_request(session, users["developer"], name="requests", version="2.31.0")
    item.package_version.status = "approved"
    session.commit()

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["db_check"].result == "pass"
    assert steps["blacklist"].result == "skipped"
    assert item.status == "approved"
    assert "pip install -i" in (item.next_action or "")


def test_step0_new_package_passes(session, users, fake_metadata):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert steps_by_code(item)["db_check"].result == "pass"


# --------------------------------------------------------------------------- шаг 1
def test_step1_blacklist_exact_name_stops_and_skips_rest(session, users, fake_metadata):
    _, item = make_request(session, users["developer"], name="colourama", version="0.4.6")

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["blacklist"].result == "fail"
    assert "Тайпсквоттинг" in steps["blacklist"].message
    for code in ("quarantine", "license", "download", "vuln_scan", "publish"):
        assert steps[code].result == "skipped"
        assert "Blacklist" in steps[code].message
    assert item.status == "blacklisted"
    assert item.package_version.status == "blacklisted"


def test_step1_blacklist_glob_any_manager(session, users, fake_metadata):
    _, item = make_request(session, users["developer"], manager="npm", name="internal-utils", version="1.0.0")
    run_pipeline(session, item)
    assert steps_by_code(item)["blacklist"].result == "fail"


def test_step1_blacklist_version_range_other_version_passes(session, users, fake_metadata):
    _, blocked = make_request(
        session, users["developer"], manager="npm", name="event-stream", version="3.3.6"
    )
    run_pipeline(session, blocked)
    assert steps_by_code(blocked)["blacklist"].result == "fail"

    _, allowed = make_request(
        session, users["developer"], manager="npm", name="event-stream", version="4.0.1"
    )
    run_pipeline(session, allowed)
    assert steps_by_code(allowed)["blacklist"].result == "pass"


def test_blacklisted_package_is_never_downloaded(session, users, fake_metadata, storage):
    _, item = make_request(session, users["developer"], name="colourama", version="0.4.6")
    run_pipeline(session, item)
    assert storage.list_objects() == []


# --------------------------------------------------------------------------- шаг 2
def test_step2_quarantine_holds_fresh_version(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=3)
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["quarantine"].result == "warn"
    assert steps["license"].result == "skipped"
    assert item.status == "quarantined"
    assert item.package_version.quarantine_until is not None
    assert "Карантин закончится" in (item.next_action or "")


def test_step2_quarantine_passes_for_old_version(session, users, fake_metadata):
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=400)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert steps_by_code(item)["quarantine"].result == "pass"


def test_step2_unknown_publish_date_goes_to_devsecops(session, users, fake_metadata):
    fake_metadata["published_at"] = None
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["quarantine"].result == "warn"
    assert item.status == "awaiting_security"


# --------------------------------------------------------------------------- шаг 3
def test_step3_allowed_license_passes(session, users, fake_metadata):
    fake_metadata["license_spdx"] = "Apache-2.0"
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert steps_by_code(item)["license"].result == "pass"
    assert item.package_version.license_spdx == "Apache-2.0"


def test_step3_unknown_license_goes_to_legal(session, users, fake_metadata):
    fake_metadata["license_spdx"] = None
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["license"].result == "warn"
    assert "не определилась" in steps["license"].message
    # Согласования параллельны: шаг лицензии не останавливает конвейер, иначе
    # DevSecOps увидел бы пакет только после решения юриста.
    assert steps["download"].result == "pass"
    assert steps["publish"].result != "pass", "без согласования лицензии публикации нет"
    assert item.status in ("awaiting_legal", "awaiting_security")


def test_step3_forbidden_license_goes_to_legal(session, users, fake_metadata):
    fake_metadata["license_spdx"] = "AGPL-3.0-only"
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert steps_by_code(item)["license"].result == "warn"
    assert item.status == "awaiting_legal"


def test_step3_notifies_legal_role(session, users, fake_metadata):
    fake_metadata["license_spdx"] = None
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    session.commit()

    events = session.query(Notification).filter(Notification.user_id == users["legal"].id).all()
    assert any(n.event == "request_awaits_legal" for n in events)


# --------------------------------------------------------------------------- шаг 4
def test_step4_downloads_to_object_storage(session, users, fake_metadata, storage):
    _, item = make_request(session, users["developer"], name="somepkg", version="1.0.0")
    run_pipeline(session, item)

    keys = [o.key for o in storage.list_objects()]
    # После успешной публикации объект удаляется — проверяем запись в БД.
    artifact = item.package_version.artifacts[0]
    assert artifact.s3_key == "pypi/somepkg/1.0.0/pkg-1.0.0.tar.gz"
    assert artifact.sha256
    assert artifact.s3_deleted_at is not None
    assert keys == []


def test_step4_checksum_mismatch_fails(session, users, fake_metadata):
    fake_metadata["checksum"] = "0" * 64
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["download"].result == "fail"
    assert "Контрольная сумма" in steps["download"].message
    assert steps["vuln_scan"].result == "skipped"
    assert item.status == "failed"


def test_step4_size_limit_fails(session, users, fake_metadata, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_artifact_size_bytes", 5)
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert steps_by_code(item)["download"].result == "fail"


# --------------------------------------------------------------------------- шаг 5
def test_step5_high_score_stops_and_notifies_devsecops(
    session, users, fake_metadata, vuln_index, finding_factory
):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)
    session.commit()

    steps = steps_by_code(item)
    assert steps["vuln_scan"].result == "fail"
    assert steps["publish"].result == "skipped"
    assert item.status == "awaiting_security"
    assert item.package_version.max_vuln_score == 98.0
    assert [v.external_id for v in item.package_version.vulnerabilities] == ["CVE-2024-0001"]
    events = session.query(Notification).filter(Notification.user_id == users["devsecops"].id).all()
    assert any(n.event == "request_awaits_security" for n in events)


def test_step5_rejection_purges_object_from_minio(
    session, users, fake_metadata, vuln_index, finding_factory, storage
):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert storage.list_objects() == []
    assert item.package_version.artifacts[0].s3_deleted_at is not None


def test_step5_below_threshold_passes(session, users, fake_metadata, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=5.0)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    steps = steps_by_code(item)
    assert steps["vuln_scan"].result == "pass"
    assert item.status == "approved"


def test_step5_stale_index_disables_auto_approval(session, users, fake_metadata, vuln_index):
    vuln_index.make_old(days=10)
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["vuln_scan"].result == "warn"
    assert "устарела" in steps["vuln_scan"].message
    assert steps["publish"].result == "skipped"
    assert item.status == "awaiting_security"


def test_step5_records_index_version(session, users, fake_metadata, vuln_index):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert item.package_version.vuln_index_version_id is not None
    step = steps_by_code(item)["vuln_scan"]
    assert step.details["index_version"] == "test-snapshot-1"


# --------------------------------------------------------------------------- шаг 6
def test_step6_publishes_and_purges_minio(session, users, fake_metadata, store, storage):
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["publish"].result == "pass"
    assert item.status == "approved"
    assert item.package_version.status == "approved"
    artifact = item.package_version.artifacts[0]
    assert artifact.nexus_url and artifact.status == "published"
    assert artifact.s3_deleted_at is not None
    assert storage.list_objects() == []
    assert store.published


def test_step6_publish_is_idempotent(session, users, fake_metadata, store):
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    published_before = dict(store.published)

    run_pipeline(session, item, from_step="download")
    assert store.published == published_before


def test_step6_failure_marks_item_failed(session, users, fake_metadata, store):
    store.fail_publish = True
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["publish"].result == "fail"
    assert item.status == "failed"


def test_full_pass_records_install_command(session, users, fake_metadata):
    _, item = make_request(session, users["developer"], name="requests", version="2.31.0")
    run_pipeline(session, item)
    assert "pip install -i" in (item.next_action or "")
    assert item.request.status == "approved"


def test_step5_missing_snapshot_goes_to_devsecops_not_failed(
    session, users, fake_metadata, vuln_index, storage
):
    """Снапшот OSV ни разу не загружался: по заданию это warn и решение DevSecOps.

    Раньше запрос к незагруженному индексу выбрасывал ошибку, шаг падал с fail и
    заявка уходила в failed — вместо очереди DevSecOps.
    """
    from app.core.errors import UpstreamError

    def not_loaded(*_args, **_kwargs):
        raise UpstreamError("Локальная база OSV не загружена")

    vuln_index.query = not_loaded
    vuln_index.version = None  # current_version() -> None
    vuln_index.stale = True

    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["download"].result == "pass"
    assert steps["vuln_scan"].result == "warn"
    assert "не загружался" in steps["vuln_scan"].message
    assert steps["publish"].result == "skipped"
    assert item.status == "awaiting_security"


def test_step5_scan_error_on_fresh_index_still_fails(
    session, users, fake_metadata, vuln_index
):
    """Если база свежая, а скан не выполнился — это настоящая ошибка, не warn."""
    from app.core.errors import UpstreamError

    def broken(*_args, **_kwargs):
        raise UpstreamError("сканер недоступен")

    vuln_index.query = broken
    vuln_index.stale = False  # снапшот актуален

    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)

    assert steps_by_code(item)["vuln_scan"].result == "fail"
    assert item.status == "failed"


def test_devsecops_can_approve_after_missing_snapshot(
    session, users, fake_metadata, vuln_index, store
):
    """Полный цикл при недоступной базе: warn -> решение DevSecOps -> публикация."""
    from app.core.errors import UpstreamError
    from app.services import decisions

    def not_loaded(*_args, **_kwargs):
        raise UpstreamError("Локальная база OSV не загружена")

    vuln_index.query = not_loaded
    vuln_index.version = None
    vuln_index.stale = True

    _, item = make_request(session, users["developer"], name="somepkg", version="1.0.0")
    run_pipeline(session, item)
    assert item.status == "awaiting_security"

    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="База OSV недоступна, риск принят"
    )

    assert item.status == "approved"
    assert steps_by_code(item)["publish"].result == "pass"
    assert store.published, "пакет должен появиться в артефактори"
