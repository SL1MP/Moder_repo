"""E2E: основной флоу от заведения пакета до установки из внутреннего репозитория."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import respx

from app.db.enums import STEP_CODES

pytestmark = pytest.mark.usefixtures("fake_metadata")


def test_happy_path_pypi(api, users, token, store, storage):
    """Разработчик заводит пакет → конвейер проходит → пакет в артефактори."""
    headers = token(users["developer"])

    created = api.post(
        "/api/v1/requests",
        json={
            "manager": "pypi",
            "packages": ["requests==2.31.0"],
            "reason": "Сервис выставления счетов, спринт 41",
        },
        headers=headers,
    )
    assert created.status_code == 202
    request_id = created.json()["request_id"]

    body = api.get(f"/api/v1/requests/{request_id}?wait=true&timeout=10", headers=headers).json()
    assert body["approved"] is True
    package = body["packages"][0]
    assert [s["result"] for s in package["steps"]] == ["pass"] * len(STEP_CODES)
    assert "pip install -i" in package["install_command"]

    # Артефакт опубликован, MinIO очищен.
    assert store.published
    assert storage.list_objects() == []

    # Повторная заявка на тот же пакет не создаётся.
    again = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["requests==2.31.0"]}, headers=headers
    ).json()
    assert again["accepted"] == 0
    assert again["packages"][0]["state"] == "already_in_base"


def test_flow_with_quarantine_then_legal_then_security(
    api, users, token, fake_metadata, vuln_index, finding_factory, store
):
    """Пакет проходит все три ручные остановки и в итоге публикуется."""
    dev = token(users["developer"])
    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=1)
    fake_metadata["license_spdx"] = None
    vuln_index.set_findings("npm", "leftpad", "1.0.0", [finding_factory(score=9.1)])

    request_id = api.post(
        "/api/v1/requests",
        json={"manager": "npm", "packages": ["leftpad@1.0.0"]},
        headers=dev,
    ).json()["request_id"]

    # 1. Карантин
    body = api.get(f"/api/v1/requests/{request_id}", headers=dev).json()
    assert body["status"] == "quarantined"
    item_id = body["packages"][0]["id"]
    api.post(
        f"/api/v1/items/{item_id}/quarantine/release",
        json={"comment": "Проверено вручную"},
        headers=token(users["devsecops"]),
    )

    # 2. Лицензия и уязвимости — согласования идут параллельно.
    body = api.get(f"/api/v1/requests/{request_id}", headers=dev).json()
    # Заявка показывает самую блокирующую из ожидаемых ролей.
    assert body["status"] == "awaiting_security"
    steps = {s["code"]: s["result"] for s in body["packages"][0]["steps"]}
    assert steps["license"] == "warn", "лицензия должна ждать юриста"
    # warn — база устарела, fail — балл выше порога; в обоих случаях решает DevSecOps.
    assert steps["vuln_scan"] in ("warn", "fail"), "уязвимости должны ждать DevSecOps"
    assert steps["download"] == "pass", (
        "конвейер обязан пройти дальше лицензии — иначе DevSecOps снова ждёт юриста"
    )

    # Пакет виден обеим ролям сразу, а не по очереди.
    legal_queue = api.get("/api/v1/queue/legal", headers=token(users["legal"])).json()
    security_queue = api.get(
        "/api/v1/queue/security", headers=token(users["devsecops"])
    ).json()
    assert item_id in [row["item_id"] for row in legal_queue]
    assert item_id in [row["item_id"] for row in security_queue]

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://example.org/LICENSE").respond(200, text="MIT License")
        claim = api.post(
            f"/api/v1/items/{item_id}/license-claim",
            json={"url": "https://example.org/LICENSE", "spdx_id": "MIT"},
            headers=dev,
        ).json()
    api.post(
        f"/api/v1/license-claims/{claim['id']}/decision",
        json={"approve": True, "comment": "Согласовано"},
        headers=token(users["legal"]),
    )

    # 3. Юрист решил — остаётся только DevSecOps.
    body = api.get(f"/api/v1/requests/{request_id}", headers=dev).json()
    assert body["status"] == "awaiting_security"
    steps = {s["code"]: s["result"] for s in body["packages"][0]["steps"]}
    assert steps["license"] == "pass", "решение юриста должно снять блокировку"
    vuln_index.set_findings("npm", "leftpad", "1.0.0", [])
    api.post(
        f"/api/v1/items/{item_id}/security-decision",
        json={"approve": True, "comment": "Ложное срабатывание"},
        headers=token(users["devsecops"]),
    )

    final = api.get(f"/api/v1/requests/{request_id}", headers=dev).json()
    assert final["approved"] is True
    assert "npm i --registry=" in final["packages"][0]["install_command"]
    assert store.published


def test_flow_blacklist_is_final(api, users, token, storage, store):
    dev = token(users["developer"])
    request_id = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["colourama==0.4.6"]}, headers=dev
    ).json()["request_id"]

    body = api.get(f"/api/v1/requests/{request_id}", headers=dev).json()
    assert body["status"] == "rejected"
    package = body["packages"][0]
    assert package["status"] == "blacklisted"
    # Пакет не скачивался и не публиковался.
    assert storage.list_objects() == []
    assert not store.published


def test_flow_revocation_after_new_cve(api, users, token, vuln_index, finding_factory, store):
    dev = token(users["developer"])
    request_id = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["latercve==1.0.0"]}, headers=dev
    ).json()["request_id"]
    assert api.get(f"/api/v1/requests/{request_id}", headers=dev).json()["approved"] is True

    # Новый снапшот OSV приносит критичную уязвимость.
    vuln_index.set_findings("pypi", "latercve", "1.0.0", [finding_factory(score=9.9)])
    from app.tasks.scheduled import rescan_approved

    assert rescan_approved()["revoked"] == 1

    version_id = api.get("/api/v1/packages?q=latercve", headers=dev).json()["items"][0]["id"]
    detail = api.get(f"/api/v1/packages/{version_id}", headers=dev).json()
    assert detail["status"] == "revoked"
    assert not store.published

    notifications = api.get("/api/v1/notifications", headers=dev).json()
    assert any(n["event"] == "package_revoked" for n in notifications["items"])
