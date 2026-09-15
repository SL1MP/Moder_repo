"""CLI сервиса: `moderctl`.

Основные команды:
  bootstrap            — справочники, бакет MinIO, репозитории артефактори, демо-данные
  import-package-list  — одноразовый импорт существующих package_list.txt как одобренных
  create-service-account — сервисная учётка для CI (fallback-вход)
  sync-osv             — загрузка снапшота базы OSV
  reload-policies      — перечитать blacklist и справочник лицензий
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import session_scope

app = typer.Typer(help="Сервис модерации внешних пакетов — служебные команды", no_args_is_help=True)
log = get_logger(__name__)


@app.callback()
def _main() -> None:
    configure_logging(get_settings().log_level)


@app.command()
def bootstrap(
    demo: bool = typer.Option(True, help="Загрузить демо-данные"),
    buckets: bool = typer.Option(True, help="Создать бакет MinIO"),
    repositories: bool = typer.Option(True, help="Создать репозитории в артефактори"),
    service_password: str = typer.Option("", help="Пароль демо-учёток (для LOCAL_AUTH_ENABLED=true)"),
) -> None:
    """Первичная настройка: справочники, хранилища, демо-данные."""
    from app.services import seeds
    from app.services.policies import reload_policies

    reload_policies()
    with session_scope() as session:
        managers = seeds.seed_managers(session)
        licenses = seeds.seed_licenses(session)
        typer.echo(f"Менеджеры: +{managers}, лицензии: +{licenses}")
        if service_password:
            seeds.seed_demo_users(session, password=service_password)
            typer.echo("Демо-учётки созданы с паролем (только для dev)")
        if demo:
            counts = seeds.seed_demo_data(session)
            typer.echo(f"Демо-данные: {counts}")

    if buckets:
        try:
            from app.adapters.object_storage import get_object_storage

            get_object_storage().ensure_bucket()
            typer.echo(f"Бакет MinIO готов: {get_settings().s3_bucket}")
        except Exception as exc:  # noqa: BLE001
            typer.secho(f"MinIO недоступен: {exc}", fg=typer.colors.YELLOW)

    if repositories:
        try:
            from app.adapters.artifact_store import get_artifact_store

            created = get_artifact_store().ensure_repositories()
            typer.echo(f"Репозитории артефактори: создано {len(created)} ({', '.join(created) or '—'})")
        except Exception as exc:  # noqa: BLE001
            typer.secho(f"Артефактори недоступен: {exc}", fg=typer.colors.YELLOW)


@app.command("import-package-list")
def import_package_list(
    path: Path = typer.Argument(..., help="Файл package_list.txt"),
    manager: str = typer.Option(..., help="pypi | npm | go | nuget"),
    actor: str = typer.Option("admin", help="Имя учётной записи для аудит-лога"),
    origin: str = typer.Option("", help="Источник (например, gitlab:group/repo:package_list.txt)"),
) -> None:
    """Одноразовый импорт существующих package_list.txt в базу как уже одобренных пакетов."""
    from app.db.models import User
    from app.services import seeds

    if not path.exists():
        typer.secho(f"Файл не найден: {path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    lines = path.read_text("utf-8").splitlines()
    with session_scope() as session:
        user = session.query(User).filter(User.username == actor).first()
        stats = seeds.import_package_list(
            session,
            manager=manager,
            lines=lines,
            actor=user,
            origin=origin or str(path),
        )
    typer.echo(
        f"Импортировано: {stats['imported']}, пропущено (уже одобрены): {stats['skipped']}, "
        f"с ошибкой формата: {stats['invalid']}"
    )


@app.command("create-service-account")
def create_service_account(
    username: str = typer.Argument(..., help="Логин сервисной учётки"),
    password: str = typer.Option(..., prompt=True, hide_input=True),
    roles: str = typer.Option("developer", help="Роли через запятую"),
) -> None:
    """Сервисная учётка для CI (работает только при LOCAL_AUTH_ENABLED=true)."""
    from app.core.security import hash_password
    from app.db.models import User
    from app.services import audit

    role_list = [r.strip() for r in roles.split(",") if r.strip()]
    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if user is None:
            user = User(username=username, roles=role_list, is_service=True)
            session.add(user)
        user.roles = role_list
        user.is_service = True
        user.password_hash = hash_password(password)
        session.flush()
        audit.record(
            session,
            action="service_account_created",
            entity_type="user",
            entity_id=user.id,
            new_value={"username": username, "roles": role_list},
            source="cli",
        )
    typer.echo(f"Сервисная учётка «{username}» готова, роли: {', '.join(role_list)}")
    if not get_settings().local_auth_enabled:
        typer.secho(
            "LOCAL_AUTH_ENABLED=false — вход по логину/паролю сейчас отключён",
            fg=typer.colors.YELLOW,
        )


@app.command("sync-osv")
def sync_osv(force: bool = typer.Option(False, help="Загрузить снапшот даже если версия та же")) -> None:
    """Загрузка снапшота базы OSV из артефактори."""
    from app.tasks.scheduled import sync_osv_snapshot

    result = sync_osv_snapshot(force)
    typer.echo(result)


@app.command("run-pending")
def run_pending(
    request_id: int = typer.Option(0, help="Только заявка с этим номером (0 = все ожидающие)"),
) -> None:
    """Прогнать конвейер по пакетам, застрявшим в очереди, синхронно.

    Штатно очередь разбирает worker, а если он молчит — сторож внутри API
    (PIPELINE_WATCHDOG_ENABLED). Эта команда нужна, когда результат хочется
    увидеть немедленно, не дожидаясь следующего прохода сторожа.
    """
    from app.db.models import RequestItem
    from app.pipeline.claim import claim_item, stale_running_seconds
    from app.pipeline.runner import run_pipeline

    stale_after = stale_running_seconds()
    with session_scope() as session:
        query = session.query(RequestItem).filter(RequestItem.status.in_(("queued", "running")))
        if request_id:
            query = query.filter(RequestItem.request_id == request_id)
        item_ids = [row.id for row in query.order_by(RequestItem.id).all()]
        if not item_ids:
            typer.echo("Ожидающих пакетов нет")
            return
        typer.echo(f"Пакетов к обработке: {len(item_ids)}")
        for item_id in item_ids:
            item = session.get(RequestItem, item_id)
            if item is None:
                continue
            typer.echo(f"  #{item.id} {item.requested_name} {item.requested_version} … ", nl=False)
            # Захват, чтобы не прогнать пакет параллельно с worker'ом или сторожем.
            if not claim_item(session, item_id, stale_running_after_seconds=stale_after):
                typer.echo("уже обрабатывается, пропущен")
                continue
            run_pipeline(session, item, source="cli")
            typer.echo(f"{item.status} (шаг: {item.current_step})")
            if item.blocked_reason:
                typer.echo(f"      причина: {item.blocked_reason}")


@app.command("queue-status")
def queue_status() -> None:
    """Кто разбирает очередь: жив ли worker и сколько пакетов зависло."""
    from app.services.watchdog import find_stuck
    from app.services.worker_health import worker_status

    status = worker_status()
    typer.echo(f"worker: {'жив' if status.alive else 'НЕ ОТВЕЧАЕТ'} — {status.detail}")
    with session_scope() as session:
        stuck = find_stuck(session, include_running=not status.alive)
    s = get_settings()
    typer.echo(
        f"зависших пакетов: {len(stuck)}"
        + (f" (id: {', '.join(str(i) for i in stuck[:20])})" if stuck else "")
    )
    typer.echo(
        "сторож: "
        + (
            f"включён, проход раз в {s.pipeline_watchdog_interval_seconds} с, "
            f"порог зависания {s.pipeline_stuck_after_seconds} с"
            if s.pipeline_watchdog_enabled
            else "выключен (PIPELINE_WATCHDOG_ENABLED=false)"
        )
    )


@app.command("queue-doctor")
def queue_doctor() -> None:
    """Полный разбор: почему пакеты не уходят из очереди. Вывод можно слать целиком."""
    from app.services.queue_doctor import diagnose, format_report

    report = diagnose()
    typer.echo(format_report(report))
    if not report.healthy:
        raise typer.Exit(code=1)


@app.command("rescan")
def rescan() -> None:
    """Перепроверка ранее одобренных пакетов по текущему снапшоту OSV."""
    from app.tasks.scheduled import rescan_approved

    typer.echo(rescan_approved())


@app.command("reload-policies")
def reload_policies_cmd() -> None:
    """Перечитать blacklist и справочник лицензий."""
    from app.services.policies import reload_policies

    typer.echo(reload_policies())


@app.command("release-quarantine")
def release_quarantine_cmd() -> None:
    """Снять карантин у версий, срок которых истёк."""
    from app.tasks.scheduled import release_quarantine

    typer.echo(release_quarantine())


def main() -> int:  # pragma: no cover - точка входа
    app()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
