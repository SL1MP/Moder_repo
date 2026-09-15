"""Аутентификация и роли.

Основной способ — OIDC (Authorization Code + PKCE) к Keycloak: SPA получает токен,
API проверяет его подпись по JWKS издателя. Группы каталога маппятся в роли
переменными `ROLE_MAPPING_*`. Fallback-вход логин/пароль — только сервисные учётки,
включается флагом `LOCAL_AUTH_ENABLED` (в prod `false`).

Права проверяются в API, а не только в UI.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthError, ConfigurationError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import User

log = get_logger(__name__)

# bcrypt учитывает только первые 72 байта пароля — обрезаем явно, а не через обёртку.
BCRYPT_MAX_BYTES = 72

LOCAL_ISSUER = "moderation-local"


@dataclass
class TokenClaims:
    subject: str
    username: str
    email: str | None
    full_name: str | None
    roles: list[str]
    groups: list[str]
    is_service: bool
    raw: dict[str, Any]


# --------------------------------------------------------------------------- JWKS
_jwks_cache: dict[str, Any] = {}
_jwks_lock = threading.Lock()
JWKS_TTL_SECONDS = 900


def _jwks() -> dict[str, Any]:
    s = get_settings()
    if not s.oidc_issuer:
        raise ConfigurationError("Не задан OIDC_ISSUER — проверка токенов невозможна")
    with _jwks_lock:
        cached = _jwks_cache.get(s.oidc_issuer)
        if cached and time.time() - cached["ts"] < JWKS_TTL_SECONDS:
            return cached["keys"]
    conf_url = f"{s.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
    with client() as http:
        conf_resp = request_with_retries("keycloak", lambda: http.get(conf_url))
        if conf_resp.status_code >= 400:
            raise AuthError(
                f"OIDC-издатель ответил {conf_resp.status_code} на {conf_url}. "
                "Проверьте OIDC_ISSUER и что realm существует в Keycloak.",
                issuer=s.oidc_issuer,
                status=conf_resp.status_code,
            )
        jwks_uri = _json_or_error(conf_resp, "конфигурацию OIDC-издателя").get("jwks_uri")
        if not jwks_uri:
            raise AuthError("В конфигурации OIDC-издателя нет jwks_uri")
        keys_resp = request_with_retries("keycloak", lambda: http.get(jwks_uri))
        if keys_resp.status_code >= 400:
            raise AuthError(
                f"OIDC-издатель ответил {keys_resp.status_code} при запросе JWKS",
                status=keys_resp.status_code,
            )
        keys = _json_or_error(keys_resp, "JWKS издателя")
    with _jwks_lock:
        _jwks_cache[s.oidc_issuer] = {"keys": keys, "ts": time.time()}
    return keys


def _json_or_error(response, what: str) -> dict[str, Any]:
    """Разбирает JSON-ответ издателя.

    Если по адресу издателя стоит прокси или балансировщик, вместо JSON может прийти
    HTML-страница с кодом 200. Без явной проверки это давало необработанное
    исключение и невнятный 500 вместо понятного сообщения.
    """
    try:
        payload = response.json()
    except ValueError as exc:
        snippet = response.text[:200].replace("\n", " ")
        raise AuthError(
            f"OIDC-издатель вернул не JSON на запрос {what}: {snippet}",
            content_type=response.headers.get("content-type"),
        ) from exc
    if not isinstance(payload, dict):
        raise AuthError(f"OIDC-издатель вернул неожиданный формат {what}")
    return payload


def reset_jwks_cache() -> None:
    with _jwks_lock:
        _jwks_cache.clear()


# --------------------------------------------------------------------------- разбор токена
def decode_token(token: str) -> TokenClaims:
    """Проверяет подпись и возвращает нормализованные claims."""
    s = get_settings()
    try:
        unverified = jwt.get_unverified_claims(token)
    except JWTError as exc:
        raise AuthError("Токен повреждён или имеет неверный формат") from exc

    if unverified.get("iss") == LOCAL_ISSUER:
        if not s.local_auth_enabled:
            raise AuthError("Локальная аутентификация отключена (LOCAL_AUTH_ENABLED=false)")
        try:
            payload = jwt.decode(token, s.local_auth_secret, algorithms=["HS256"], issuer=LOCAL_ISSUER)
        except JWTError as exc:
            raise AuthError(f"Локальный токен не прошёл проверку: {exc}") from exc
        return _claims_from_local(payload)

    try:
        payload = jwt.decode(
            token,
            _jwks(),
            algorithms=["RS256", "RS512", "ES256"],
            # Внутренний и внешний адреса Keycloak дают разный `iss` — принимаем оба.
            issuer=s.accepted_issuers or None,
            options={"verify_aud": False},  # Keycloak кладёт клиент в azp, а не в aud
        )
    except JWTError as exc:
        raise AuthError(f"Токен не прошёл проверку: {exc}") from exc
    return _claims_from_oidc(payload)


def _claims_from_oidc(payload: dict[str, Any]) -> TokenClaims:
    s = get_settings()
    groups: list[str] = []
    for key in ("groups", "roles"):
        value = payload.get(key)
        if isinstance(value, list):
            groups.extend(str(v).lstrip("/") for v in value)
    realm_roles = ((payload.get("realm_access") or {}).get("roles")) or []
    groups.extend(str(r) for r in realm_roles)
    for client_roles in (payload.get("resource_access") or {}).values():
        groups.extend(str(r) for r in (client_roles.get("roles") or []))

    roles = sorted({role for g in groups if (role := s.role_for_group(g))})
    username = (
        payload.get("preferred_username")
        or payload.get("email")
        or payload.get("client_id")
        or payload.get("azp")
        or payload["sub"]
    )
    return TokenClaims(
        subject=payload["sub"],
        username=str(username),
        email=payload.get("email"),
        full_name=payload.get("name"),
        roles=roles,
        groups=sorted(set(groups)),
        is_service=bool(payload.get("client_id")) and not payload.get("email"),
        raw=payload,
    )


def _claims_from_local(payload: dict[str, Any]) -> TokenClaims:
    return TokenClaims(
        subject=payload["sub"],
        username=payload.get("username") or payload["sub"],
        email=payload.get("email"),
        full_name=payload.get("name"),
        roles=list(payload.get("roles") or []),
        groups=[],
        is_service=True,
        raw=payload,
    )


def issue_local_token(user: User) -> tuple[str, int]:
    """Локальный JWT для сервисной учётки. Возвращает (токен, срок жизни в секундах)."""
    s = get_settings()
    if not s.local_auth_enabled:
        raise AuthError("Локальная аутентификация отключена (LOCAL_AUTH_ENABLED=false)")
    ttl = s.local_auth_token_ttl_minutes * 60
    now = datetime.now(UTC)
    payload = {
        "iss": LOCAL_ISSUER,
        "sub": f"local:{user.username}",
        "username": user.username,
        "email": user.email,
        "name": user.full_name,
        "roles": list(user.roles or []),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    return jwt.encode(payload, s.local_auth_secret, algorithm="HS256"), ttl


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(_pw_bytes(password), password_hash.encode())
    except (ValueError, TypeError):
        return False


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_pw_bytes(password), bcrypt.gensalt()).decode()


def _pw_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


# --------------------------------------------------------------------------- пользователи
def sync_user(session: Session, claims: TokenClaims) -> User:
    """Заводит/обновляет пользователя по claims токена."""
    user = (
        session.query(User).filter(User.subject == claims.subject).first()
        or session.query(User).filter(User.username == claims.username).first()
    )
    if user is None:
        user = User(
            subject=claims.subject,
            username=claims.username,
            email=claims.email,
            full_name=claims.full_name,
            roles=claims.roles,
            is_service=claims.is_service,
        )
        session.add(user)
    else:
        user.subject = user.subject or claims.subject
        user.email = claims.email or user.email
        user.full_name = claims.full_name or user.full_name
        if claims.roles:
            user.roles = claims.roles
        elif not user.roles:
            user.roles = []
    user.last_login_at = utcnow()
    session.flush()
    return user


def primary_role(user: User) -> str | None:
    for role in ("admin", "devsecops", "legal", "developer"):
        if user.has_role(role):
            return role
    return None
