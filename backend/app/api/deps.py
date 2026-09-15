"""Зависимости FastAPI: текущий пользователь, роли, лимиты."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.errors import AuthError, ForbiddenError
from app.core.ratelimit import check_rate_limit
from app.core.security import decode_token, primary_role, sync_user
from app.db.models import User
from app.db.session import get_db

ROLE_TITLES = {
    "admin": "администратор",
    "devsecops": "DevSecOps",
    "legal": "юрист",
    "developer": "разработчик",
}


def get_current_user(
    request: Request,
    session: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("Не передан Bearer-токен в заголовке Authorization")
    token = authorization.split(" ", 1)[1].strip()
    claims = decode_token(token)
    user = sync_user(session, claims)
    if not user.is_active:
        raise ForbiddenError(f"Учётная запись «{user.username}» отключена")
    request.state.user = user
    request.state.actor_role = primary_role(user)
    return user


def require_roles(*roles: str) -> Callable[[User], User]:
    """Проверка прав на стороне API. `admin` имеет доступ ко всему."""

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.has_role("admin") or user.has_role(*roles):
            return user
        needed = ", ".join(ROLE_TITLES.get(r, r) for r in roles)
        raise ForbiddenError(f"Действие доступно ролям: {needed}")

    return dependency


def require_any_role(user: User = Depends(get_current_user)) -> User:
    """Любая из четырёх ролей: добавлять пакеты может любая роль."""
    if not user.roles:
        raise ForbiddenError(
            "У учётной записи нет ни одной роли сервиса. Проверьте членство в группах каталога "
            "и переменные ROLE_MAPPING_*"
        )
    return user


def rate_limited(user: User = Depends(get_current_user)) -> User:
    check_rate_limit(str(user.id))
    return user


def actor_role(request: Request) -> str | None:
    return getattr(request.state, "actor_role", None)


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
