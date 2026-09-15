"""Аутентификация: параметры OIDC для SPA, профиль, fallback-вход для сервисных учёток."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user
from app.core.config import get_settings
from app.core.errors import AuthError
from app.core.security import issue_local_token, primary_role, verify_password
from app.db.base import utcnow
from app.db.models import User
from app.db.session import get_db
from app.schemas import LocalLoginIn, MeOut, TokenOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["Доступ"])


@router.get("/config", summary="Параметры OIDC для SPA (Authorization Code + PKCE)")
def auth_config() -> dict[str, object]:
    s = get_settings()
    return {
        "issuer": s.browser_issuer,
        "client_id": s.oidc_client_id,
        "scopes": ["openid", "profile", "email"],
        "flow": "authorization_code_pkce",
        "local_auth_enabled": s.local_auth_enabled,
        "app_name": s.app_name,
        "app_env": s.app_env,
        "gitlab_enabled": bool(s.gitlab_url and s.gitlab_oauth_client_id),
        "role_mapping": {
            "admin": s.role_mapping_admin,
            "devsecops": s.role_mapping_devsecops,
            "legal": s.role_mapping_legal,
            "developer": s.role_mapping_developer,
        },
    }


@router.get("/me", response_model=MeOut, summary="Текущий пользователь и его роли")
def me(user: User = Depends(get_current_user)) -> MeOut:
    return MeOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        roles=list(user.roles or []),
        is_service=user.is_service,
        gitlab_connected=bool(user.gitlab_refresh_token_enc or user.gitlab_access_token_enc),
    )


@router.post("/token", response_model=TokenOut, summary="Fallback-вход (только сервисные учётки)")
def local_login(
    request: Request,
    payload: LocalLoginIn,
    session: Session = Depends(get_db),
) -> TokenOut:
    s = get_settings()
    if not s.local_auth_enabled:
        raise AuthError(
            "Локальная аутентификация отключена. Используйте вход через SSO "
            "(LOCAL_AUTH_ENABLED=false)"
        )
    user = session.query(User).filter(User.username == payload.username).first()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        audit.record(
            session,
            action="local_login_failed",
            entity_type="user",
            entity_id=payload.username,
            actor_name=payload.username,
            new_value={"result": "denied"},
            source="api",
            ip=client_ip(request),
        )
        session.commit()
        raise AuthError("Неверный логин или пароль")

    token, ttl = issue_local_token(user)
    user.last_login_at = utcnow()
    audit.record(
        session,
        action="local_login",
        entity_type="user",
        entity_id=user.id,
        actor=user,
        actor_role=primary_role(user),
        new_value={"result": "ok"},
        source="api",
        ip=client_ip(request),
    )
    session.commit()
    return TokenOut(access_token=token, expires_in=ttl, roles=list(user.roles or []))
