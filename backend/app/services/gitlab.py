"""Интеграция с GitLab — только чтение.

OAuth-приложение GitLab, подключение из профиля пользователя (scope `read_repository`),
чтение файла зависимостей из приватного проекта от имени пользователя с указанием
ветки/тега/commit sha. Refresh-токены шифруются (Fernet) и не возвращаются в API.
Ничего не коммитим и MR не открываем.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import quote, urlencode

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import decrypt, encrypt
from app.core.errors import ConfigurationError, NotFoundError, UpstreamError, ValidationError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import User

log = get_logger(__name__)
SCOPES = "read_api read_repository"
MAX_FILE_BYTES = 5 * 1024 * 1024


@dataclass
class GitlabFile:
    project: str
    path: str
    ref: str
    content: bytes
    commit_id: str | None = None
    last_commit_id: str | None = None


def _require_config() -> None:
    s = get_settings()
    if not (s.gitlab_url and s.gitlab_oauth_client_id and s.gitlab_oauth_client_secret):
        raise ConfigurationError(
            "Интеграция с GitLab не настроена: задайте GITLAB_URL, GITLAB_OAUTH_CLIENT_ID "
            "и GITLAB_OAUTH_CLIENT_SECRET"
        )


def authorize_url(state: str | None = None) -> tuple[str, str]:
    """URL для подключения GitLab из профиля пользователя."""
    _require_config()
    s = get_settings()
    state = state or secrets.token_urlsafe(24)
    params = {
        "client_id": s.gitlab_oauth_client_id,
        "redirect_uri": s.gitlab_oauth_redirect_uri,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    }
    return f"{s.gitlab_url.rstrip('/')}/oauth/authorize?{urlencode(params)}", state


def exchange_code(session: Session, user: User, code: str) -> User:
    """Обменивает код на токены и сохраняет их в зашифрованном виде."""
    _require_config()
    s = get_settings()
    url = f"{s.gitlab_url.rstrip('/')}/oauth/token"
    data = {
        "client_id": s.gitlab_oauth_client_id,
        "client_secret": s.gitlab_oauth_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": s.gitlab_oauth_redirect_uri,
    }
    with client() as http:
        resp = request_with_retries("gitlab", lambda: http.post(url, data=data))
    if resp.status_code >= 400:
        raise UpstreamError(
            f"GitLab отклонил обмен кода на токен ({resp.status_code})", status=resp.status_code
        )
    payload = resp.json()
    access = payload.get("access_token")
    refresh = payload.get("refresh_token")
    if not access:
        raise UpstreamError("GitLab не вернул access_token")

    user.gitlab_access_token_enc = encrypt(access)
    user.gitlab_refresh_token_enc = encrypt(refresh) if refresh else None
    expires_in = int(payload.get("expires_in") or 0)
    user.gitlab_token_expires_at = utcnow() + timedelta(seconds=expires_in) if expires_in else None
    user.gitlab_username = _fetch_username(access)
    session.flush()
    return user


def _fetch_username(access_token: str) -> str | None:
    s = get_settings()
    url = f"{s.gitlab_url.rstrip('/')}/api/v4/user"
    with client() as http:
        resp = request_with_retries(
            "gitlab", lambda: http.get(url, headers={"Authorization": f"Bearer {access_token}"})
        )
    if resp.status_code >= 400:
        return None
    return resp.json().get("username")


def disconnect(session: Session, user: User) -> User:
    user.gitlab_access_token_enc = None
    user.gitlab_refresh_token_enc = None
    user.gitlab_token_expires_at = None
    user.gitlab_username = None
    session.flush()
    return user


def _access_token(session: Session, user: User) -> str:
    if not user.gitlab_access_token_enc:
        raise ValidationError(
            "GitLab не подключён. Откройте профиль и выполните подключение (scope read_repository)"
        )
    expires = user.gitlab_token_expires_at
    if expires is not None:
        now = utcnow()
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=now.tzinfo)
        if expires <= now:
            return _refresh(session, user)
    return decrypt(user.gitlab_access_token_enc)


def _refresh(session: Session, user: User) -> str:
    _require_config()
    if not user.gitlab_refresh_token_enc:
        raise ValidationError("Срок действия токена GitLab истёк — подключите GitLab заново")
    s = get_settings()
    url = f"{s.gitlab_url.rstrip('/')}/oauth/token"
    data = {
        "client_id": s.gitlab_oauth_client_id,
        "client_secret": s.gitlab_oauth_client_secret,
        "refresh_token": decrypt(user.gitlab_refresh_token_enc),
        "grant_type": "refresh_token",
        "redirect_uri": s.gitlab_oauth_redirect_uri,
    }
    with client() as http:
        resp = request_with_retries("gitlab", lambda: http.post(url, data=data))
    if resp.status_code >= 400:
        raise ValidationError("Не удалось обновить токен GitLab — подключите GitLab заново")
    payload = resp.json()
    access = payload["access_token"]
    user.gitlab_access_token_enc = encrypt(access)
    if payload.get("refresh_token"):
        user.gitlab_refresh_token_enc = encrypt(payload["refresh_token"])
    expires_in = int(payload.get("expires_in") or 0)
    user.gitlab_token_expires_at = utcnow() + timedelta(seconds=expires_in) if expires_in else None
    session.flush()
    return access


def read_file(session: Session, user: User, *, project: str, path: str, ref: str = "HEAD") -> GitlabFile:
    """Читает файл зависимостей от имени пользователя. Ничего не пишет в репозиторий."""
    _require_config()
    s = get_settings()
    token = _access_token(session, user)
    project_id = quote(str(project), safe="")
    file_path = quote(path.lstrip("/"), safe="")
    url = f"{s.gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/repository/files/{file_path}/raw"
    with client() as http:
        resp = request_with_retries(
            "gitlab",
            lambda: http.get(
                url, params={"ref": ref}, headers={"Authorization": f"Bearer {token}"}
            ),
        )
    if resp.status_code == 404:
        raise NotFoundError(
            f"Файл «{path}» не найден в проекте {project} (ref: {ref}) либо нет доступа"
        )
    if resp.status_code == 403:
        raise ValidationError(
            "GitLab отказал в доступе: у пользователя нет прав read_repository на этот проект"
        )
    if resp.status_code >= 400:
        raise UpstreamError(f"GitLab ответил {resp.status_code}", status=resp.status_code)
    content = resp.content
    if len(content) > MAX_FILE_BYTES:
        raise ValidationError(f"Файл больше {MAX_FILE_BYTES} байт")
    return GitlabFile(
        project=str(project),
        path=path,
        ref=ref,
        content=content,
        commit_id=resp.headers.get("x-gitlab-commit-id"),
        last_commit_id=resp.headers.get("x-gitlab-last-commit-id"),
    )
