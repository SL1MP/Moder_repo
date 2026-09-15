"""База пакетов: поиск и проверка наличия (способ «проверка по базе»)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.errors import InvalidPackageFormat, NotFoundError, ValidationError
from app.db.models import PackageVersion, User
from app.db.session import get_db
from app.managers.base import ParsedEntry
from app.managers.registry import all_plugins, detect_manager_by_file, get_plugin
from app.schemas import (
    CheckPackagesIn,
    ManagerOut,
    PackageSearchOut,
    PackageVersionOut,
)
from app.services import packages as packages_service
from app.services.policies import get_license_policy

router = APIRouter(tags=["Пакеты"])


@router.get("/managers", response_model=list[ManagerOut], summary="Поддерживаемые менеджеры")
def list_managers() -> list[ManagerOut]:
    return [
        ManagerOut(
            code=p.code,
            title=p.title,
            entry_format=p.entry_format,
            dependency_files=list(p.dependency_files),
            osv_ecosystem=p.osv_ecosystem,
        )
        for p in all_plugins()
    ]


@router.get("/managers/detect", summary="Определить менеджер по имени файла зависимостей")
def detect_manager(filename: str = Query(min_length=1)) -> dict[str, str | None]:
    return {"filename": filename, "manager": detect_manager_by_file(filename)}


@router.get("/packages", response_model=PackageSearchOut, summary="Поиск по базе пакетов")
def search_packages(
    session: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    q: str | None = Query(default=None, description="Имя пакета или его часть"),
    manager: str | None = None,
    version: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
) -> PackageSearchOut:
    items, total = packages_service.search_versions(
        session, query=q, manager=manager, version=version, status=status, limit=limit, offset=offset
    )
    return PackageSearchOut(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            PackageVersionOut(**packages_service.version_summary(session, item)) for item in items
        ],
    )


@router.post("/packages/check", summary="Проверить наличие пакетов в базе")
def check_packages(
    payload: CheckPackagesIn,
    session: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Разбирает записи и говорит по каждой: есть в базе (и с каким статусом) или нет."""
    plugin = get_plugin(payload.manager)
    result: list[dict[str, object]] = []
    if not payload.packages:
        raise ValidationError("Список packages пуст")

    for raw in payload.packages:
        if isinstance(raw, str):
            label = raw
            entry = plugin.try_parse_entry(raw)
        else:
            label = f"{raw.name} {raw.version}"
            try:
                entry = ParsedEntry(raw=label, ref=plugin.make_ref(raw.name, raw.version))
            except InvalidPackageFormat as exc:
                entry = ParsedEntry(raw=label, error=exc.message, expected_format=plugin.entry_format)

        if entry.ref is None:
            result.append(
                {
                    "raw": label,
                    "state": "invalid_format",
                    "message": entry.error,
                    "expected_format": plugin.entry_format,
                }
            )
            continue
        existing = packages_service.find_version(session, entry.ref)
        if existing is None:
            result.append(
                {
                    "raw": label,
                    "state": "not_found",
                    "name": entry.ref.display_name,
                    "version": entry.ref.raw_version,
                    "message": "В базе нет — нужно заводить заявку.",
                }
            )
            continue
        # Состояние по существу (можно ставить / идёт проверка / не прошёл), а не
        # просто «запись найдена»: строка появляется ещё до всех проверок.
        payload_item: dict[str, object] = {
            "raw": label,
            "name": entry.ref.display_name,
            "version": entry.ref.raw_version,
            **packages_service.check_state(session, existing),
        }
        result.append(payload_item)
    return {"manager": plugin.code, "packages": result}


@router.get("/packages/{version_id}", response_model=PackageVersionOut, summary="Карточка пакета")
def get_package_version(
    version_id: int,
    session: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PackageVersionOut:
    version = session.get(PackageVersion, version_id)
    if version is None:
        raise NotFoundError(f"Версия пакета #{version_id} не найдена")
    return PackageVersionOut(**packages_service.version_summary(session, version))


@router.get("/licenses", summary="Справочник лицензий (автодополнение SPDX)")
def list_licenses(_user: User = Depends(get_current_user)) -> dict[str, object]:
    policy = get_license_policy()
    return {
        "path": policy.path,
        "loaded_at": policy.loaded_at,
        "error": policy.error,
        "allowed": sorted(policy.allowed.values(), key=lambda x: x["spdx_id"]),
        "forbidden": sorted(policy.forbidden.values(), key=lambda x: x["spdx_id"]),
    }
