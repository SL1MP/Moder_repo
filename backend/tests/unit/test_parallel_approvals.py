"""Согласования юристов и DevSecOps идут параллельно.

Раньше конвейер останавливался на шаге лицензии, и DevSecOps видел пакет только
после того, как юрист поставит апрув: две роли ждали друг друга по очереди.
Теперь шаг лицензии не останавливает прогон — пакет доходит до проверки
уязвимостей, и обе очереди наполняются сразу. Публикация не состоится, пока не
снята каждая блокировка.
"""

from __future__ import annotations

import pytest

from app.pipeline.blockers import pending_blockers
from app.pipeline.runner import run_pipeline
from app.services import decisions
from tests.factories import make_request, steps_by_code

pytestmark = pytest.mark.usefixtures("policies", "store", "storage", "vuln_index", "notifier")


def _needs_both(session, users, fake_metadata, vuln_index, finding_factory):
    """Пакет, которому нужны оба согласования: лицензия и уязвимости."""
    fake_metadata["license_spdx"] = None
    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [finding_factory(score=9.8)])
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    return item


def test_license_does_not_stop_the_pipeline(session, users, fake_metadata):
    """Шаг лицензии ждёт юриста, но скачивание и проверка уже выполнены."""
    fake_metadata["license_spdx"] = None
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["license"].result == "warn"
    assert steps["download"].result == "pass", "конвейер обязан пройти дальше лицензии"
    assert steps["vuln_scan"].result == "pass"


def test_publication_waits_for_the_license(session, users, fake_metadata, store):
    """Проверки пройдены, но без лицензии публикации нет."""
    fake_metadata["license_spdx"] = None
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["publish"].result != "pass"
    assert not store.published, "пакет с несогласованной лицензией опубликован быть не может"
    assert item.status == "awaiting_legal"


def test_both_roles_see_the_package_at_once(
    session, users, fake_metadata, vuln_index, finding_factory
):
    """Обе блокировки висят одновременно — ни одна роль не ждёт другую."""
    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)

    blockers = pending_blockers(item)
    steps = steps_by_code(item)
    assert "license" in blockers
    assert steps["vuln_scan"].result in ("warn", "fail")
    # Статусом показывается самая блокирующая из ожидаемых ролей.
    assert item.status == "awaiting_security"


def test_legal_first_then_security_publishes(
    session, users, fake_metadata, vuln_index, finding_factory, store
):
    """Порядок решений не важен: сначала юрист, потом DevSecOps."""
    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)

    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT",
        comment=None, actor=users["developer"],
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"], comment="Ок")
    assert item.status != "approved", "остаётся решение DevSecOps"
    assert "license" not in pending_blockers(item)

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [])
    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Риск принят"
    )

    assert item.status == "approved"
    assert store.published


def test_security_first_then_legal_publishes(
    session, users, fake_metadata, vuln_index, finding_factory, store
):
    """И обратный порядок тоже доводит пакет до публикации."""
    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)

    vuln_index.set_findings("pypi", "somepkg", "1.0.0", [])
    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Риск принят"
    )
    assert item.status != "approved", "остаётся решение юриста"
    assert not store.published

    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT",
        comment=None, actor=users["developer"],
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"], comment="Ок")

    assert item.status == "approved"
    assert store.published


def test_license_claim_allowed_while_security_holds_the_status(
    session, users, fake_metadata, vuln_index, finding_factory
):
    """Статус пакета — awaiting_security, но приложить лицензию всё равно можно."""
    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)
    assert item.status == "awaiting_security"

    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT",
        comment=None, actor=users["developer"],
    )

    assert claim.status == "pending"
    # Статус не понижается: пакет всё ещё ждёт DevSecOps, и это важнее.
    assert item.status == "awaiting_security"


def test_quarantine_still_stops_the_pipeline(session, users, fake_metadata):
    """Карантин — не согласование, а срок: параллелить тут нечего."""
    from datetime import UTC, datetime, timedelta

    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=3)
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["quarantine"].result == "warn"
    assert steps["download"].result == "skipped", "во время карантина пакет не качаем"
    assert item.status == "quarantined"


def test_api_payload_lists_both_pending_decisions(
    session, users, fake_metadata, vuln_index, finding_factory
):
    """Карточка обязана отдавать список открытых решений, а не только статус.

    Интерфейс строит блоки решений по этому списку. Пока его не было, блок
    выбирался по статусу — а он один, и более блокирующий `awaiting_security`
    скрывал блок юриста: апрув нельзя было поставить, пока не решит DevSecOps.
    """
    from app.services.requests_service import request_payload

    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)
    session.commit()

    payload = request_payload(session, item.request)
    entry = next(p for p in payload["packages"] if p["id"] == item.id)

    assert "license" in entry["pending"], "юрист должен видеть свой блок"
    assert "vuln_scan" in entry["pending"], "DevSecOps должен видеть свой блок"
    # Статус показывает только более блокирующую роль — на нём одном UI строить нельзя.
    assert entry["status"] == "awaiting_security"


def test_api_payload_drops_decision_once_made(
    session, users, fake_metadata, vuln_index, finding_factory
):
    """Снятая блокировка уходит из списка — блок решения пропадает из карточки."""
    from app.services.requests_service import request_payload

    item = _needs_both(session, users, fake_metadata, vuln_index, finding_factory)
    claim = decisions.claim_license(
        session, item, url="https://example.org/L", spdx_id="MIT",
        comment=None, actor=users["developer"],
    )
    decisions.decide_license(session, claim, approve=True, actor=users["legal"], comment="Ок")
    session.commit()

    payload = request_payload(session, item.request)
    entry = next(p for p in payload["packages"] if p["id"] == item.id)

    assert "license" not in entry["pending"]
    assert "vuln_scan" in entry["pending"], "решение DevSecOps всё ещё нужно"
