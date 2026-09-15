"""Хелперы для тестов: создание заявки с одним пакетом."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import ModerationRequest, RequestItem, User
from app.managers.registry import get_plugin
from app.pipeline.runner import ensure_steps
from app.services import packages


def make_request(
    session: Session,
    author: User,
    *,
    manager: str = "pypi",
    name: str = "somepkg",
    version: str = "1.0.0",
    reason: str = "Тестовая заявка",
    dependency_kind: str = "direct",
) -> tuple[ModerationRequest, RequestItem]:
    ref = get_plugin(manager).make_ref(name, version)
    pv, _ = packages.get_or_create_version(session, ref)
    request = ModerationRequest(
        author_id=author.id,
        author_role="developer",
        manager=manager,
        reason=reason,
        status="pending",
        source="api",
    )
    session.add(request)
    session.flush()
    item = RequestItem(
        request_id=request.id,
        package_version_id=pv.id,
        requested_name=ref.display_name,
        requested_version=ref.raw_version,
        dependency_kind=dependency_kind,
        status="queued",
    )
    session.add(item)
    session.flush()
    ensure_steps(session, item)
    session.commit()
    return request, item


def steps_by_code(item: RequestItem) -> dict[str, object]:
    return {s.step_code: s for s in item.steps}
