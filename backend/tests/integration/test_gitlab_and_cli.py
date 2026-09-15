"""Интеграция с GitLab (только чтение) и одноразовый CLI-импорт package_list.txt."""

from __future__ import annotations

import pytest
import respx

from app.core.config import get_settings
from app.core.crypto import decrypt
from app.db.models import AuditLog, PackageVersion, User
from app.services import gitlab as gitlab_service
from app.services import seeds

pytestmark = pytest.mark.usefixtures("fake_metadata")

GO_MOD = b"""module example.com/svc

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/sys v0.18.0 // indirect
)
"""


@pytest.fixture
def gitlab_config(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "gitlab_url", "https://gitlab.example.org")
    monkeypatch.setattr(s, "gitlab_oauth_client_id", "client-id")
    monkeypatch.setattr(s, "gitlab_oauth_client_secret", "client-secret")
    monkeypatch.setattr(s, "gitlab_oauth_redirect_uri", "http://localhost:8080/api/v1/gitlab/callback")
    return s


def test_authorize_url_contains_read_scopes(api, users, token, gitlab_config):
    body = api.get("/api/v1/gitlab/authorize", headers=token(users["developer"])).json()
    assert "response_type=code" in body["authorize_url"]
    assert "read_repository" in body["authorize_url"]
    assert body["state"]


def test_authorize_without_configuration_reports_error(api, users, token):
    resp = api.get("/api/v1/gitlab/authorize", headers=token(users["developer"]))
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "configuration_error"


@respx.mock
def test_callback_stores_encrypted_tokens(api, users, token, gitlab_config, session):
    respx.post("https://gitlab.example.org/oauth/token").respond(
        json={
            "access_token": "at-123",
            "refresh_token": "rt-456",
            "expires_in": 7200,
            "token_type": "bearer",
        }
    )
    respx.get("https://gitlab.example.org/api/v4/user").respond(json={"username": "ivanov"})

    resp = api.get("/api/v1/gitlab/callback?code=abcdef12", headers=token(users["developer"]))
    assert resp.status_code == 200
    assert resp.json()["gitlab_username"] == "ivanov"

    session.expire_all()
    user = session.query(User).filter(User.username == "dev").one()
    # Токены зашифрованы и не совпадают с исходными значениями.
    assert user.gitlab_refresh_token_enc and user.gitlab_refresh_token_enc != "rt-456"
    assert decrypt(user.gitlab_refresh_token_enc) == "rt-456"

    # В API токены не отдаются.
    status = api.get("/api/v1/gitlab/status", headers=token(users["developer"])).json()
    assert status["connected"] is True
    assert "rt-456" not in str(status)
    assert "at-123" not in str(status)


@respx.mock
def test_request_from_gitlab_file(api, users, token, gitlab_config, session):
    from app.core.crypto import encrypt

    users["developer"].gitlab_access_token_enc = encrypt("at-123")
    session.commit()

    respx.get(
        "https://gitlab.example.org/api/v4/projects/group%2Fsvc/repository/files/go.mod/raw"
    ).respond(200, content=GO_MOD, headers={"x-gitlab-commit-id": "deadbeef"})

    resp = api.post(
        "/api/v1/gitlab/requests",
        json={"project": "group/svc", "path": "go.mod", "ref": "main", "reason": "перевод на внутренний"},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["manager"] == "go"
    # Транзитивная (`// indirect`) не попадает в заявку без include_transitive.
    assert {p["name"] for p in body["packages"]} == {"github.com/gin-gonic/gin"}
    assert any("Файл прочитан из GitLab" in w for w in body["warnings"])


@respx.mock
def test_gitlab_file_not_found(api, users, token, gitlab_config, session):
    from app.core.crypto import encrypt

    users["developer"].gitlab_access_token_enc = encrypt("at-123")
    session.commit()
    respx.get(
        "https://gitlab.example.org/api/v4/projects/group%2Fsvc/repository/files/go.mod/raw"
    ).respond(404)

    resp = api.post(
        "/api/v1/gitlab/requests",
        json={"project": "group/svc", "path": "go.mod", "ref": "main"},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 404


def test_gitlab_requires_connection(api, users, token, gitlab_config):
    resp = api.post(
        "/api/v1/gitlab/requests",
        json={"project": "group/svc", "path": "go.mod"},
        headers=token(users["developer"]),
    )
    assert resp.status_code == 422
    assert "GitLab не подключён" in resp.json()["error"]["message"]


def test_read_file_refreshes_expired_token(session, users, gitlab_config):
    from datetime import UTC, datetime, timedelta

    from app.core.crypto import encrypt

    user = users["developer"]
    user.gitlab_access_token_enc = encrypt("old-at")
    user.gitlab_refresh_token_enc = encrypt("rt-456")
    user.gitlab_token_expires_at = datetime.now(UTC) - timedelta(minutes=5)
    session.commit()

    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://gitlab.example.org/oauth/token").respond(
            json={"access_token": "new-at", "refresh_token": "rt-789", "expires_in": 7200}
        )
        mock.get(
            "https://gitlab.example.org/api/v4/projects/1/repository/files/go.mod/raw"
        ).respond(200, content=GO_MOD)
        file = gitlab_service.read_file(session, user, project="1", path="go.mod", ref="main")

    assert file.content == GO_MOD
    assert decrypt(user.gitlab_access_token_enc) == "new-at"
    assert decrypt(user.gitlab_refresh_token_enc) == "rt-789"


# --------------------------------------------------------------------------- CLI-импорт
def test_import_package_list_marks_approved_with_audit(session, users):
    lines = [
        "# существующий список",
        "requests==2.31.0",
        "pydantic==2.6.4",
        "broken-line",
        "",
    ]
    stats = seeds.import_package_list(
        session,
        manager="pypi",
        lines=lines,
        actor=users["admin"],
        origin="gitlab:group/repo:package_list.txt",
    )
    session.commit()

    assert stats == {"imported": 2, "skipped": 0, "invalid": 1}
    approved = (
        session.query(PackageVersion).filter(PackageVersion.status == "approved").all()
    )
    assert len(approved) == 2

    entries = session.query(AuditLog).filter(AuditLog.action == "package_imported").all()
    assert len(entries) == 2
    assert all(e.source == "cli" for e in entries)
    assert all("package_list.txt" in (e.comment or "") for e in entries)


def test_import_package_list_is_idempotent(session, users):
    lines = ["lodash@4.17.21"]
    first = seeds.import_package_list(
        session, manager="npm", lines=lines, actor=users["admin"], origin="package_list.txt"
    )
    second = seeds.import_package_list(
        session, manager="npm", lines=lines, actor=users["admin"], origin="package_list.txt"
    )
    assert first["imported"] == 1
    assert second["skipped"] == 1


def test_seed_managers_and_licenses(session):
    from app.db.models import License, PackageManager

    assert seeds.seed_managers(session) == 4
    assert seeds.seed_managers(session) == 0  # идемпотентно
    assert session.query(PackageManager).count() == 4

    created = seeds.seed_licenses(session)
    assert created > 0
    assert session.query(License).filter(License.spdx_id == "MIT", License.allowed.is_(True)).count() == 1


def test_seed_demo_data(session):
    counts = seeds.seed_demo_data(session)
    session.commit()
    assert counts["approved"] == 5
    assert counts["requests"] == 1
    assert session.query(PackageVersion).filter(PackageVersion.status == "quarantined").count() == 1
