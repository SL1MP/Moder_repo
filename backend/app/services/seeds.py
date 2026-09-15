"""Сиды: справочники, демо-данные, импорт существующих `package_list.txt`."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.base import utcnow
from app.db.models import (
    License,
    ModerationRequest,
    PackageManager,
    RequestItem,
    User,
)
from app.managers.registry import all_plugins, get_plugin
from app.pipeline.runner import ensure_steps, recompute_request_status
from app.services import audit, packages
from app.services.policies import get_license_policy

DEMO_USERS = [
    ("dev.ivanov", "Иванов Иван", ["developer"], "dev.ivanov@example.com"),
    ("sec.petrov", "Петров Пётр", ["devsecops"], "sec.petrov@example.com"),
    ("legal.sidorova", "Сидорова Анна", ["legal"], "legal.sidorova@example.com"),
    ("admin", "Администратор сервиса", ["admin"], "admin@example.com"),
]


def seed_managers(session: Session) -> int:
    created = 0
    for plugin in all_plugins():
        row = session.execute(
            select(PackageManager).where(PackageManager.code == plugin.code)
        ).scalars().first()
        if row is None:
            session.add(
                PackageManager(
                    code=plugin.code,
                    title=plugin.title,
                    entry_format=plugin.entry_format,
                    enabled=True,
                )
            )
            created += 1
        else:
            row.title = plugin.title
            row.entry_format = plugin.entry_format
    session.flush()
    return created


def seed_licenses(session: Session) -> int:
    """Переносит справочник из licenses.yml в таблицу `license` (для автодополнения)."""
    policy = get_license_policy()
    created = 0
    for entry in [*policy.allowed.values(), *policy.forbidden.values()]:
        row = session.execute(
            select(License).where(License.spdx_id == entry["spdx_id"])
        ).scalars().first()
        if row is None:
            row = License(spdx_id=entry["spdx_id"])
            session.add(row)
            created += 1
        row.name = entry.get("name")
        row.url = entry.get("url")
        row.notes = entry.get("notes")
        row.allowed = bool(entry.get("allowed"))
    session.flush()
    return created


def seed_demo_users(session: Session, *, password: str | None = None) -> list[User]:
    users: list[User] = []
    for username, full_name, roles, email in DEMO_USERS:
        user = session.execute(select(User).where(User.username == username)).scalars().first()
        if user is None:
            user = User(username=username, full_name=full_name, email=email, roles=roles)
            session.add(user)
        user.roles = roles
        user.full_name = full_name
        user.email = email
        if password:
            user.password_hash = hash_password(password)
            user.is_service = True
        users.append(user)
    session.flush()
    return users


def seed_demo_data(session: Session) -> dict[str, int]:
    """Демо-данные: одобренные пакеты и заявка, остановленная на карантине."""
    users = seed_demo_users(session)
    author = next(u for u in users if u.has_role("developer"))
    counts = {"approved": 0, "requests": 0}

    approved = [
        ("pypi", "requests", "2.31.0", "Apache-2.0"),
        ("pypi", "pydantic", "2.6.4", "MIT"),
        ("npm", "lodash", "4.17.21", "MIT"),
        ("go", "github.com/gin-gonic/gin", "v1.9.1", "MIT"),
        ("nuget", "Newtonsoft.Json", "13.0.3", "MIT"),
    ]
    for manager, name, version, spdx in approved:
        plugin = get_plugin(manager)
        ref = plugin.make_ref(name, version)
        pv, created = packages.get_or_create_version(session, ref)
        if created or pv.status != "approved":
            pv.status = "approved"
            pv.license_spdx = spdx
            pv.license_source = "registry"
            pv.published_at = utcnow() - timedelta(days=200)
            pv.approved_at = utcnow() - timedelta(days=30)
            pv.max_vuln_score = 0.0
            counts["approved"] += 1

    # Заявка в карантине: свежая версия, конвейер остановлен на шаге 2.
    plugin = get_plugin("pypi")
    ref = plugin.make_ref("httpx", "0.27.0")
    pv, _ = packages.get_or_create_version(session, ref)
    pv.status = "quarantined"
    pv.published_at = utcnow() - timedelta(days=3)
    pv.quarantine_until = utcnow() + timedelta(days=11)
    pv.license_spdx = "BSD-3-Clause"

    existing = session.execute(
        select(ModerationRequest).where(ModerationRequest.reason == "Демо-заявка: карантин")
    ).scalars().first()
    if existing is None:
        request = ModerationRequest(
            author_id=author.id,
            author_role="developer",
            manager="pypi",
            reason="Демо-заявка: карантин",
            status="quarantined",
            source="cli",
        )
        session.add(request)
        session.flush()
        item = RequestItem(
            request_id=request.id,
            package_version_id=pv.id,
            requested_name="httpx",
            requested_version="0.27.0",
            status="quarantined",
            current_step="quarantine",
            blocked_reason="Карантин 14 дн. не истёк",
            next_action="Проверка продолжится автоматически после окончания карантина.",
            waiting_since=utcnow(),
        )
        session.add(item)
        session.flush()
        ensure_steps(session, item)
        for step in item.steps:
            if step.step_code == "db_check":
                step.result, step.message = "pass", "В базе не найден, заявка принята к проверке."
            elif step.step_code == "blacklist":
                step.result, step.message = "pass", "Совпадений с правилами blacklist нет."
            elif step.step_code == "quarantine":
                step.result = "warn"
                step.message = "Версия опубликована 3 дн. назад, карантин 14 дн. не истёк."
            else:
                step.result = "skipped"
                step.message = "Не выполнялся: конвейер остановлен на шаге «Карантин»."
            step.finished_at = utcnow()
        recompute_request_status(session, request)
        counts["requests"] += 1

    audit.record(
        session,
        action="demo_data_seeded",
        entity_type="configuration",
        new_value=counts,
        source="cli",
    )
    session.flush()
    return counts


def import_package_list(
    session: Session,
    *,
    manager: str,
    lines: list[str],
    actor: User | None,
    origin: str,
) -> dict[str, int]:
    """Одноразовый импорт существующего `package_list.txt` как уже одобренных пакетов.

    Источник фиксируется в аудит-логе; после импорта файлы в GitLab не читаются.
    """
    plugin = get_plugin(manager)
    stats = {"imported": 0, "skipped": 0, "invalid": 0}
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        entry = plugin.try_parse_entry(line)
        if entry.ref is None:
            stats["invalid"] += 1
            continue
        version, created = packages.get_or_create_version(session, entry.ref)
        if not created and version.status == "approved":
            stats["skipped"] += 1
            continue
        version.status = "approved"
        version.approved_at = utcnow()
        version.license_source = version.license_source or "manual"
        version.status_reason = f"Импортирован из {origin} как ранее одобренный"
        stats["imported"] += 1
        audit.record(
            session,
            action="package_imported",
            entity_type="package_version",
            entity_id=version.id,
            actor=actor,
            new_value={
                "manager": manager,
                "name": entry.ref.display_name,
                "version": entry.ref.raw_version,
                "origin": origin,
            },
            source="cli",
            comment=f"Импорт из {origin}",
        )
    session.flush()
    return stats
