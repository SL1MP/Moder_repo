"""API очередей, решений, обсуждений, уведомлений, настроек и аудита."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.usefixtures("fake_metadata")


def _create(api, token, user, packages, manager="pypi"):
    resp = api.post(
        "/api/v1/requests",
        json={"manager": manager, "packages": packages, "reason": "тест"},
        headers=token(user),
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["request_id"]


# --------------------------------------------------------------------------- очереди
def test_security_queue_and_decision(api, users, token, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "riskypkg", "1.0.0", [finding_factory(score=9.5)])
    request_id = _create(api, token, users["developer"], ["riskypkg==1.0.0"])

    queue = api.get("/api/v1/queue/security", headers=token(users["devsecops"])).json()
    assert len(queue) == 1
    entry = queue[0]
    assert entry["name"] == "riskypkg"
    assert entry["max_vuln_score"] == 95.0
    assert entry["waiting_hours"] is not None

    # Разработчику очередь DevSecOps недоступна.
    assert api.get("/api/v1/queue/security", headers=token(users["developer"])).status_code == 403

    vuln_index.set_findings("pypi", "riskypkg", "1.0.0", [])
    decided = api.post(
        f"/api/v1/items/{entry['item_id']}/security-decision",
        json={"approve": True, "comment": "Не применимо к нашему сценарию"},
        headers=token(users["devsecops"]),
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "approved"

    body = api.get(f"/api/v1/requests/{request_id}", headers=token(users["developer"])).json()
    assert body["approved"] is True


def test_security_rejection_requires_comment(api, users, token, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "riskypkg", "1.0.0", [finding_factory(score=9.5)])
    _create(api, token, users["developer"], ["riskypkg==1.0.0"])
    item_id = api.get("/api/v1/queue/security", headers=token(users["devsecops"])).json()[0]["item_id"]

    resp = api.post(
        f"/api/v1/items/{item_id}/security-decision",
        json={"approve": False},
        headers=token(users["devsecops"]),
    )
    assert resp.status_code == 422
    assert "комментарий обязателен" in resp.json()["error"]["message"]


def test_quarantine_release_via_api(api, users, token, fake_metadata):
    from datetime import UTC, datetime, timedelta

    fake_metadata["published_at"] = datetime.now(UTC) - timedelta(days=1)
    _create(api, token, users["developer"], ["freshpkg==1.0.0"])

    queue = api.get("/api/v1/queue/security", headers=token(users["devsecops"])).json()
    quarantined = [q for q in queue if q["status"] == "quarantined"]
    assert quarantined

    resp = api.post(
        f"/api/v1/items/{quarantined[0]['item_id']}/quarantine/release",
        json={"comment": "Проверено вручную"},
        headers=token(users["devsecops"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"


# --------------------------------------------------------------------------- лицензии
def test_legal_queue_claim_and_approval(api, users, token, fake_metadata, respx_mock=None):
    fake_metadata["license_spdx"] = None
    request_id = _create(api, token, users["developer"], ["nolicense==1.0.0"])

    queue = api.get("/api/v1/queue/legal", headers=token(users["legal"])).json()
    assert len(queue) == 1
    item_id = queue[0]["item_id"]

    import respx

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://example.org/LICENSE").respond(200, text="MIT License\n\nPermission...")
        claim = api.post(
            f"/api/v1/items/{item_id}/license-claim",
            json={
                "url": "https://example.org/LICENSE",
                "spdx_id": "MIT",
                "comment": "Файл лицензии в корне",
            },
            headers=token(users["developer"]),
        )
    assert claim.status_code == 200, claim.text
    claim_body = claim.json()
    assert claim_body["status"] == "pending"
    assert "MIT License" in claim_body["snapshot_text"]

    decided = api.post(
        f"/api/v1/license-claims/{claim_body['id']}/decision",
        json={"approve": True, "comment": "Согласовано"},
        headers=token(users["legal"]),
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "approved"

    body = api.get(f"/api/v1/requests/{request_id}", headers=token(users["developer"])).json()
    assert body["approved"] is True
    assert body["packages"][0]["license_spdx"] == "MIT"


def test_license_claim_rejects_unreachable_url(api, users, token, fake_metadata):
    import respx

    fake_metadata["license_spdx"] = None
    _create(api, token, users["developer"], ["nolicense2==1.0.0"])
    item_id = api.get("/api/v1/queue/legal", headers=token(users["legal"])).json()[0]["item_id"]

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://example.org/private").respond(403)
        resp = api.post(
            f"/api/v1/items/{item_id}/license-claim",
            json={"url": "https://example.org/private"},
            headers=token(users["developer"]),
        )
    assert resp.status_code == 422
    assert "недоступна без авторизации" in resp.json()["error"]["message"]


def test_licenses_catalogue(api, users, token):
    body = api.get("/api/v1/licenses", headers=token(users["developer"])).json()
    allowed = {row["spdx_id"] for row in body["allowed"]}
    assert "MIT" in allowed and "Apache-2.0" in allowed
    assert any(row["spdx_id"].startswith("AGPL") for row in body["forbidden"])


# --------------------------------------------------------------------------- обсуждения
def test_comments_thread_and_mentions(api, users, token):
    request_id = _create(api, token, users["developer"], ["commented==1.0.0"])
    body = api.get(f"/api/v1/requests/{request_id}", headers=token(users["developer"])).json()
    item_id = body["packages"][0]["id"]

    posted = api.post(
        f"/api/v1/requests/{request_id}/comments",
        json={"body": "Нужна эта версия, @sec посмотри пожалуйста", "request_item_id": item_id},
        headers=token(users["developer"]),
    )
    assert posted.status_code == 200, posted.text
    assert posted.json()["mentions"] == ["sec"]

    listed = api.get(
        f"/api/v1/requests/{request_id}/comments", headers=token(users["devsecops"])
    ).json()
    assert len(listed) == 1

    # Упомянутый получил уведомление.
    notifications = api.get("/api/v1/notifications", headers=token(users["devsecops"])).json()
    assert any(n["event"] == "comment_added" for n in notifications["items"])

    # Чужой разработчик обсуждение не видит.
    assert (
        api.get(f"/api/v1/requests/{request_id}/comments", headers=token(users["developer2"])).status_code
        == 403
    )


def test_comment_edit_and_delete(api, users, token):
    request_id = _create(api, token, users["developer"], ["edited==1.0.0"])
    comment = api.post(
        f"/api/v1/requests/{request_id}/comments",
        json={"body": "первый вариант"},
        headers=token(users["developer"]),
    ).json()

    edited = api.patch(
        f"/api/v1/comments/{comment['id']}",
        json={"body": "исправленный вариант"},
        headers=token(users["developer"]),
    ).json()
    assert edited["body"] == "исправленный вариант"
    assert edited["is_edited"] is False  # внутри окна правки пометки нет

    deleted = api.delete(
        f"/api/v1/comments/{comment['id']}", headers=token(users["developer"])
    ).json()
    assert deleted["deleted"] is True
    assert deleted["body"] == "Сообщение удалено"

    # Чужой комментарий править нельзя.
    other = api.post(
        f"/api/v1/requests/{request_id}/comments",
        json={"body": "от DevSecOps"},
        headers=token(users["devsecops"]),
    ).json()
    assert (
        api.patch(
            f"/api/v1/comments/{other['id']}",
            json={"body": "подмена"},
            headers=token(users["developer"]),
        ).status_code
        == 403
    )


# --------------------------------------------------------------------------- уведомления
def test_notifications_and_counters(api, users, token, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "notifypkg", "1.0.0", [finding_factory(score=9.9)])
    _create(api, token, users["developer"], ["notifypkg==1.0.0"])

    body = api.get("/api/v1/notifications", headers=token(users["devsecops"])).json()
    assert body["unread"] >= 1
    ids = [n["id"] for n in body["items"]]

    counters = api.get("/api/v1/queue/counters", headers=token(users["devsecops"])).json()
    assert counters["security"] == 1
    assert counters["unread_notifications"] >= 1

    marked = api.post(
        "/api/v1/notifications/read", json={"ids": ids}, headers=token(users["devsecops"])
    ).json()
    assert marked["updated"] == len(ids)
    assert api.get("/api/v1/notifications", headers=token(users["devsecops"])).json()["unread"] == 0


# --------------------------------------------------------------------------- база пакетов
def test_package_search_and_check(api, users, token):
    _create(api, token, users["developer"], ["searchable==1.2.3"])

    found = api.get("/api/v1/packages?q=searchable", headers=token(users["developer"])).json()
    assert found["total"] == 1
    assert found["items"][0]["status"] == "approved"
    assert "pip install -i" in found["items"][0]["install_command"]

    check = api.post(
        "/api/v1/packages/check",
        json={"manager": "pypi", "packages": ["searchable==1.2.3", "missing==9.9.9", "broken"]},
        headers=token(users["developer"]),
    ).json()
    rows = {row["raw"]: row for row in check["packages"]}
    assert rows["searchable==1.2.3"]["state"] == "approved"
    assert "pip install -i" in rows["searchable==1.2.3"]["install_command"]
    assert rows["missing==9.9.9"]["state"] == "not_found"
    assert rows["broken"]["state"] == "invalid_format"


def test_managers_endpoint(api, users, token):
    body = api.get("/api/v1/managers", headers=token(users["developer"])).json()
    assert {m["code"] for m in body} == {"pypi", "npm", "go", "nuget"}
    assert api.get(
        "/api/v1/managers/detect?filename=go.sum", headers=token(users["developer"])
    ).json()["manager"] == "go"


def test_revoke_package(api, users, token):
    _create(api, token, users["developer"], ["revokable==1.0.0"])
    version_id = api.get("/api/v1/packages?q=revokable", headers=token(users["developer"])).json()[
        "items"
    ][0]["id"]

    resp = api.post(
        f"/api/v1/packages/{version_id}/revoke",
        json={"approve": False, "comment": "Критичная CVE"},
        headers=token(users["devsecops"]),
    )
    assert resp.status_code == 200
    detail = api.get(f"/api/v1/packages/{version_id}", headers=token(users["developer"])).json()
    assert detail["status"] == "revoked"


# --------------------------------------------------------------------------- настройки и аудит
def test_settings_are_read_only_with_env_names(api, users, token):
    rows = api.get("/api/v1/settings", headers=token(users["developer"])).json()
    by_env = {row["env"]: row for row in rows}
    assert by_env["QUARANTINE_DAYS"]["value"] == 14
    assert by_env["ARTIFACT_TOKEN"]["secret"] is True
    assert by_env["ARTIFACT_TOKEN"]["value"] in ("задано", "не задано")
    # Эндпоинтов записи настроек нет.
    assert api.post("/api/v1/settings", json={}, headers=token(users["admin"])).status_code == 405


def test_policies_endpoint_reports_blacklist_and_index(api, users, token):
    body = api.get("/api/v1/settings/policies", headers=token(users["devsecops"])).json()
    assert any(rule["name"] == "colourama" for rule in body["blacklist"]["rules"])
    assert body["vuln_index"]["source"] == "snapshot"
    assert body["vuln_index"]["max_staleness_days"] == 3


def test_system_status_reports_queue_health(api, users, token):
    """Экран «Настройка» должен показывать, кто разбирает очередь."""
    body = api.get("/api/v1/system/status", headers=token(users["developer"])).json()
    assert body["worker"]["alive"] is True  # в тестах eager-режим
    assert body["watchdog"]["enabled"] is True
    assert body["queue"]["stuck_items"] == 0


def test_queue_sweep_requires_admin(api, users, token):
    assert api.post("/api/v1/admin/queue-sweep", headers=token(users["developer"])).status_code == 403
    resp = api.post("/api/v1/admin/queue-sweep", headers=token(users["admin"]))
    assert resp.status_code == 200
    assert resp.json()["stuck"] == 0
    rows = api.get("/api/v1/admin/audit?limit=50", headers=token(users["admin"])).json()
    assert any(row["action"] == "queue_swept" for row in rows)


def test_health_reports_worker(api):
    body = api.get("/health").json()
    assert body["checks"]["worker"] == "ok"


def test_admin_reload_requires_admin(api, users, token):
    assert api.post("/api/v1/admin/reload", headers=token(users["developer"])).status_code == 403
    resp = api.post("/api/v1/admin/reload", headers=token(users["admin"]))
    assert resp.status_code == 200
    assert resp.json()["blacklist"]["rules"] >= 1


def test_audit_log_records_actions(api, users, token):
    _create(api, token, users["developer"], ["audited==1.0.0"])
    assert api.get("/api/v1/admin/audit", headers=token(users["developer"])).status_code == 403

    rows = api.get("/api/v1/admin/audit?limit=50", headers=token(users["admin"])).json()
    actions = {row["action"] for row in rows}
    assert "request_created" in actions
    created = next(row for row in rows if row["action"] == "request_created")
    assert created["actor_name"] == "dev"
    assert created["source_title"] == "REST API"
    assert created["new_value"]["packages"] == ["audited==1.0.0"]


def test_blacklisted_package_reports_final_decision(api, users, token):
    request_id = _create(api, token, users["developer"], ["colourama==0.4.6"])
    body = api.get(f"/api/v1/requests/{request_id}", headers=token(users["developer"])).json()
    package = body["packages"][0]
    assert package["status"] == "blacklisted"
    assert "Решение окончательное" in package["next_action"]
    blacklist_step = next(s for s in package["steps"] if s["code"] == "blacklist")
    assert blacklist_step["result"] == "fail"
    assert blacklist_step["details"]["rule"]["name"] == "colourama"


def test_health_and_metrics(api):
    health = api.get("/health").json()
    assert health["status"] == "ok"
    assert health["checks"]["database"] == "ok"
    metrics = api.get("/metrics")
    assert metrics.status_code == 200
    assert "moderation_http_requests_total" in metrics.text


def test_auth_config_and_me(api, users, token):
    config = api.get("/api/v1/auth/config").json()
    assert config["flow"] == "authorization_code_pkce"
    assert config["role_mapping"]["admin"] == "moderation-admin"

    me = api.get("/api/v1/auth/me", headers=token(users["legal"])).json()
    assert me["username"] == "legal"
    assert me["roles"] == ["legal"]
    assert me["gitlab_connected"] is False


def test_local_login(api, users):
    resp = api.post("/api/v1/auth/token", json={"username": "sec", "password": "secret"})
    assert resp.status_code == 200
    assert resp.json()["roles"] == ["devsecops"]

    bad = api.post("/api/v1/auth/token", json={"username": "sec", "password": "wrong"})
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "unauthorized"


def test_unhandled_exception_returns_error_envelope(engine, users, token, monkeypatch):
    """Даже необработанное исключение отдаётся в едином формате с request_id.

    Иначе клиент получает plain-text «Internal Server Error» и видит бесполезное
    «Ошибка запроса (500)» без кода и без request_id, по которому искать в логах.
    """
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import packages as packages_service

    def boom(*_args, **_kwargs):
        raise RuntimeError("сломалось внутри")

    monkeypatch.setattr(packages_service, "search_versions", boom)

    # raise_server_exceptions=False: Starlette после хендлера повторно поднимает
    # исключение (чтобы traceback попал в лог), а нам нужно увидеть тело ответа.
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/packages?q=any", headers=token(users["developer"]))

    assert resp.status_code == 500
    error = resp.json()["error"]
    assert error["code"] == "internal_error"
    assert error["details"]["error_type"] == "RuntimeError"
    assert error["request_id"]
    assert resp.headers.get("x-request-id") == error["request_id"]

    # Упавший запрос учтён в метриках — иначе 500-е не видны на графиках.
    from app.core.metrics import render_metrics

    assert b'status="500"' in render_metrics()


def test_check_distinguishes_pending_from_approved(
    api, users, token, fake_metadata, vuln_index, finding_factory
):
    """Запись в базе появляется до проверок — check не должен звать это «есть в базе».

    Иначе разработчик читает «found» как «можно ставить», хотя пакет ещё на модерации
    или вовсе её не прошёл.
    """
    headers = token(users["developer"])

    # 1) Пакет застрял на модерации: ждёт DevSecOps.
    vuln_index.set_findings("pypi", "risky", "1.0.0", [finding_factory(score=9.9)])
    rid = _create(api, token, users["developer"], ["risky==1.0.0"])

    # 2) Пакет прошёл конвейер и одобрен.
    _create(api, token, users["developer"], ["cleanpkg==1.0.0"])

    check = api.post(
        "/api/v1/packages/check",
        json={"manager": "pypi", "packages": ["risky==1.0.0", "cleanpkg==1.0.0", "nosuch==1.0.0"]},
        headers=headers,
    ).json()
    rows = {row["raw"]: row for row in check["packages"]}

    pending = rows["risky==1.0.0"]
    assert pending["state"] == "in_progress"
    assert pending["request_id"] == rid
    assert "Ставить нельзя" in pending["message"]
    assert "install_command" not in pending

    approved = rows["cleanpkg==1.0.0"]
    assert approved["state"] == "approved"
    assert "pip install -i" in approved["install_command"]

    assert rows["nosuch==1.0.0"]["state"] == "not_found"


def test_check_reports_blocked_package(api, users, token):
    """Запрещённый blacklist-ом пакет — состояние blocked с причиной."""
    headers = token(users["developer"])
    _create(api, token, users["developer"], ["colourama==0.4.6"])

    row = api.post(
        "/api/v1/packages/check",
        json={"manager": "pypi", "packages": ["colourama==0.4.6"]},
        headers=headers,
    ).json()["packages"][0]

    assert row["state"] == "blocked"
    assert row["status"] == "blacklisted"
    assert "Ставить нельзя" in row["message"]
    assert "install_command" not in row
