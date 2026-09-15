"""Интеграционные тесты REST API добавления пакетов (раздел 6)."""

from __future__ import annotations

import json

import pytest

from app.db.enums import STEP_CODES

pytestmark = pytest.mark.usefixtures("fake_metadata")

PACKAGE_LOCK = json.dumps(
    {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"lodash": "^4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/nanoid": {"version": "3.3.7"},
        },
    }
).encode()


def test_requires_authentication(api):
    resp = api.post("/api/v1/requests", json={"manager": "pypi", "packages": ["requests==2.31.0"]})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_create_request_structured_form(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        json={
            "manager": "pypi",
            "packages": [{"name": "requests", "version": "2.31.0"}, {"name": "pydantic", "version": "2.6.4"}],
            "reason": "Сервис выставления счетов, спринт 41",
        },
        headers=token(users["developer"]),
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["accepted"] == 2
    assert body["status_url"] == f"/api/v1/requests/{body['request_id']}"
    assert {p["state"] for p in body["packages"]} == {"new"}


def test_create_request_short_string_form(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["requests==2.31.0", "pydantic==2.6.4"]},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2


def test_invalid_format_is_reported_with_expected_format(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["requests==2.31.0", "lodash@4.17.21"]},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 202
    body = resp.json()
    invalid = [p for p in body["packages"] if p["state"] == "invalid_format"]
    assert len(invalid) == 1
    assert invalid[0]["expected_format"] == "name==version"
    assert body["accepted"] == 1


def test_already_in_base_is_skipped_with_link_and_command(api, users, token):
    headers = token(users["developer"])
    first = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["requests==2.31.0"]},
        headers=headers,
    )
    assert first.status_code == 202
    status = api.get(f"/api/v1/requests/{first.json()['request_id']}", headers=headers).json()
    assert status["approved"] is True

    second = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["requests==2.31.0"]},
        headers=headers,
    )
    body = second.json()
    assert body["accepted"] == 0
    assert body["skipped_already_in_base"] == 1
    entry = body["packages"][0]
    assert entry["state"] == "already_in_base"
    assert entry["link"].startswith("/api/v1/packages/")
    assert "pip install -i" in entry["install_command"]


def test_create_request_from_file_skips_transitive(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        data={"manager": "npm", "reason": "из lock-файла", "include_transitive": "false"},
        files={"file": ("package-lock.json", PACKAGE_LOCK, "application/json")},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    names = {p["name"] for p in body["packages"]}
    assert names == {"lodash"}
    assert any("Транзитивные зависимости" in w for w in body["warnings"])


def test_create_request_from_file_with_transitive(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        data={"manager": "npm", "include_transitive": "true"},
        files={"file": ("package-lock.json", PACKAGE_LOCK, "application/json")},
        headers=token(users["developer"]),
    )
    body = resp.json()
    assert {p["name"] for p in body["packages"]} == {"lodash", "nanoid"}
    kinds = {p["name"]: p["dependency_kind"] for p in body["packages"]}
    assert kinds["nanoid"] == "transitive"


def test_file_without_manager_is_rejected(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        data={},
        files={"file": ("package-lock.json", PACKAGE_LOCK, "application/json")},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_unknown_manager(api, users, token):
    resp = api.post(
        "/api/v1/requests",
        json={"manager": "cargo", "packages": ["serde==1.0"]},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "unknown_manager"


def test_empty_packages(api, users, token):
    resp = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": []}, headers=token(users["developer"])
    )
    assert resp.status_code == 422


def test_idempotency_key_returns_same_request(api, users, token):
    headers = {**token(users["developer"]), "Idempotency-Key": "ci-build-42"}
    first = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["urllib3==2.2.1"]}, headers=headers
    )
    assert first.status_code == 202
    second = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["urllib3==2.2.1"]}, headers=headers
    )
    assert second.status_code == 200
    assert second.json()["request_id"] == first.json()["request_id"]
    assert "Idempotency-Key" in second.json()["packages"][0]["message"]


def test_status_contains_steps_and_next_action(api, users, token, vuln_index, finding_factory):
    vuln_index.set_findings("pypi", "vulnpkg", "1.0.0", [finding_factory(score=9.8, fixed=["2.0.0"])])
    headers = token(users["developer"])
    created = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["vulnpkg==1.0.0"]}, headers=headers
    ).json()

    body = api.get(f"/api/v1/requests/{created['request_id']}", headers=headers).json()
    assert body["status"] == "awaiting_security"
    assert body["approved"] is False
    package = body["packages"][0]
    assert package["status_title"] == "Ждёт DevSecOps"
    assert package["vulnerabilities"][0]["id"] == "CVE-2024-0001"
    assert "2.0.0" in package["next_action"]
    codes = [s["code"] for s in package["steps"]]
    # Порядок и состав шагов — из справочника: добавление шага не должно
    # требовать правки списка в тесте, а вот расхождение с конвейером должно.
    assert codes == list(STEP_CODES)
    assert [s["result"] for s in package["steps"]][-1] == "skipped"


def test_wait_true_returns_final_status(api, users, token):
    headers = token(users["developer"])
    created = api.post(
        "/api/v1/requests", json={"manager": "pypi", "packages": ["waitpkg==1.0.0"]}, headers=headers
    ).json()
    body = api.get(
        f"/api/v1/requests/{created['request_id']}?wait=true&timeout=5", headers=headers
    ).json()
    assert body["approved"] is True
    assert body["status"] == "approved"


def test_developer_cannot_see_others_request(api, users, token):
    created = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["otherpkg==1.0.0"]},
        headers=token(users["developer"]),
    ).json()

    resp = api.get(f"/api/v1/requests/{created['request_id']}", headers=token(users["developer2"]))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


def test_devsecops_sees_all_requests(api, users, token):
    api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["seenpkg==1.0.0"]},
        headers=token(users["developer"]),
    )
    resp = api.get("/api/v1/requests", headers=token(users["devsecops"]))
    assert resp.status_code == 200
    assert any(r["author"] == "dev" for r in resp.json())


def test_package_limit_enforced(api, users, token, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_packages_per_request", 2)
    resp = api.post(
        "/api/v1/requests",
        json={"manager": "pypi", "packages": ["a==1.0", "b==1.0", "c==1.0"]},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "limit_exceeded"


def test_upload_size_limit_enforced(api, users, token, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_size_bytes", 10)
    resp = api.post(
        "/api/v1/requests",
        data={"manager": "npm"},
        files={"file": ("package-lock.json", PACKAGE_LOCK, "application/json")},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 413


def test_rate_limit(api, users, token, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_requests_per_minute", 2)
    headers = token(users["developer"])
    codes = [
        api.post(
            "/api/v1/requests",
            json={"manager": "pypi", "packages": [f"pkg{i}==1.0.0"]},
            headers=headers,
        ).status_code
        for i in range(4)
    ]
    assert 429 in codes
