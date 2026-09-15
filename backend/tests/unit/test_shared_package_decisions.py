"""Решение роли выносится по версии пакета, а не по заявке.

Тот же пакет могут заказать несколько человек. Подтверждённая лицензия,
разрешение DevSecOps и снятие карантина пишутся в `PackageVersion` и относятся
ко всем, кто эту версию заказал. Раньше возобновлялся только тот пакет, из
которого пришло решение, и одинаковый пакет в чужой заявке висел
заблокированным навсегда, хотя вердикт для него уже был вынесен.
"""

from __future__ import annotations

import pytest

from app.db.models import LicenseClaim, RequestItem
from app.services import decisions
from tests.factories import make_request

pytestmark = pytest.mark.usefixtures(
    "policies", "store", "storage", "vuln_index", "notifier", "fake_metadata"
)

PKG = {"name": "sharedpkg", "version": "2.0.0"}


def _two_requests_on_one_package(session, users, status: str):
    """Две заявки разных авторов на один и тот же пакет в одном состоянии."""
    _, first = make_request(session, users["developer"], **PKG)
    _, second = make_request(session, users["admin"], **PKG)
    assert first.package_version_id == second.package_version_id, "должна быть одна версия"
    for item in (first, second):
        item.status = status
        item.package_version.status = status
    session.commit()
    return first, second


def test_license_approval_unblocks_the_same_package_in_another_request(session, users):
    """Юрист подтвердил лицензию в одной заявке — во второй пакет тоже сдвигается."""
    first, second = _two_requests_on_one_package(session, users, "awaiting_legal")
    claim = LicenseClaim(
        package_version_id=first.package_version_id,
        request_item_id=first.id,
        claimed_by_id=users["developer"].id,
        url="https://example.com/LICENSE",
        spdx_id="MIT",
        status="pending",
    )
    session.add(claim)
    session.commit()

    decisions.decide_license(session, claim, approve=True, actor=users["legal"])
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, first.id).status != "awaiting_legal"
    assert session.get(RequestItem, second.id).status != "awaiting_legal", (
        "пакет во второй заявке остался ждать юриста — это и есть дефект"
    )


def test_license_rejection_also_reaches_the_other_request(session, users):
    """Отклонение лицензии тоже относится ко всем, кто заказал версию."""
    first, second = _two_requests_on_one_package(session, users, "awaiting_legal")
    claim = LicenseClaim(
        package_version_id=first.package_version_id,
        request_item_id=first.id,
        claimed_by_id=users["developer"].id,
        url="https://example.com/LICENSE",
        status="pending",
    )
    session.add(claim)
    session.commit()

    decisions.decide_license(
        session, claim, approve=False, actor=users["legal"], comment="Лицензия несовместима"
    )
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, second.id).status == "rejected"
    assert session.get(RequestItem, second.id).blocked_reason == "Лицензия несовместима"


def test_security_approval_unblocks_the_other_request(session, users):
    """Разрешение DevSecOps записано на версии — второй пакет ждать не должен."""
    first, second = _two_requests_on_one_package(session, users, "awaiting_security")

    decisions.decide_security(
        session, first, approve=True, actor=users["devsecops"], comment="Риск принят"
    )
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, second.id).status != "awaiting_security"


def test_security_rejection_reaches_the_other_request(session, users):
    first, second = _two_requests_on_one_package(session, users, "awaiting_security")

    decisions.decide_security(
        session, first, approve=False, actor=users["devsecops"], comment="Критическая CVE"
    )
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, second.id).status == "rejected"


def test_quarantine_release_unblocks_the_other_request(session, users):
    """Карантин снимается с версии пакета, а не с одной заявки."""
    first, second = _two_requests_on_one_package(session, users, "quarantined")

    decisions.release_quarantine(session, first, actor=users["devsecops"], comment="Проверено")
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, second.id).status != "quarantined"


def test_unrelated_package_is_not_touched(session, users):
    """Решение не должно задевать пакеты, к которым не относится."""
    first, _ = _two_requests_on_one_package(session, users, "awaiting_security")
    _, other = make_request(session, users["developer"], name="otherpkg", version="1.0.0")
    other.status = "awaiting_security"
    session.commit()

    decisions.decide_security(session, first, approve=True, actor=users["devsecops"], comment="ок")
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, other.id).status == "awaiting_security"


def test_siblings_in_other_states_are_left_alone(session, users):
    """Пакет той же версии, ждущий другого решения, трогать нельзя."""
    first, second = _two_requests_on_one_package(session, users, "awaiting_security")
    second.status = "quarantined"
    session.commit()

    decisions.decide_security(session, first, approve=True, actor=users["devsecops"], comment="ок")
    session.commit()
    session.expire_all()

    assert session.get(RequestItem, second.id).status == "quarantined"
