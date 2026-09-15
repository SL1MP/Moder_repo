"""Разбор одной командой: почему пакеты не уходят из очереди.

`queue-status` отвечает на вопрос «жив ли worker» по heartbeat в Redis. Этого
мало: heartbeat может молчать при живом worker'е (старый образ без сигнала
`worker_ready`), а живой worker может слушать не те очереди — тогда задачи
копятся в Redis, и снаружи это опять выглядит как «проверка идёт вечно».

Здесь собирается всё сразу — heartbeat, доступность брокера, длина каждой
очереди, ответ самого worker'а на `inspect` и список очередей, которые он
реально слушает, — и по этим данным печатается вывод: что именно сломано и
что с этим делать. Отчёт рассчитан на то, чтобы его целиком отправили в
поддержку, не собирая вывод пяти разных команд вручную.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.worker_health import WorkerStatus, worker_status

log = get_logger(__name__)

# Очереди, в которые маршрутизируются задачи (см. task_routes в celery_app).
PIPELINE_QUEUE = "moderation"
MAINTENANCE_QUEUE = "maintenance"
KNOWN_QUEUES = (PIPELINE_QUEUE, MAINTENANCE_QUEUE)

INSPECT_TIMEOUT_SECONDS = 5.0


@dataclass
class DoctorReport:
    """Собранное состояние очереди плюс вывод о причине."""

    worker: WorkerStatus
    eager: bool
    broker_ok: bool
    broker_detail: str
    queue_depths: dict[str, int] = field(default_factory=dict)
    inspect_ok: bool = False
    inspect_detail: str = ""
    consumed_queues: dict[str, list[str]] = field(default_factory=dict)
    stuck: list[int] = field(default_factory=list)
    publish_broker: str = ""
    publish_queue: str = ""
    verdict: str = ""
    hints: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.hints

    def to_dict(self) -> dict[str, object]:
        return {
            "worker": self.worker.to_dict(),
            "eager": self.eager,
            "broker_ok": self.broker_ok,
            "broker_detail": self.broker_detail,
            "queue_depths": self.queue_depths,
            "inspect_ok": self.inspect_ok,
            "inspect_detail": self.inspect_detail,
            "consumed_queues": self.consumed_queues,
            "stuck": self.stuck,
            "publish_broker": self.publish_broker,
            "publish_queue": self.publish_queue,
            "verdict": self.verdict,
            "hints": self.hints,
            "healthy": self.healthy,
        }


def mask_url(url: str) -> str:
    """Прячет пароль: отчёт пересылают целиком, credentials в нём не нужны."""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    creds, _, host = rest.rpartition("@")
    user = creds.partition(":")[0]
    return f"{scheme}://{user}:***@{host}" if scheme else f"{user}:***@{host}"


def _broker_client():
    """Клиент того Redis, в который Celery реально публикует задачи.

    Отдельный шов от `worker_health._redis`: тот ходит по `REDIS_URL`, а
    очередь надо мерить по `CELERY_BROKER_URL`. Это разные настройки, и при
    расхождении (другая база, другой хост) отчёт показывал бы честный ноль,
    пока сообщения копятся там, куда никто не смотрит.
    """
    import redis

    return redis.Redis.from_url(
        get_settings().celery_broker_url,
        socket_timeout=2,
        socket_connect_timeout=2,
        decode_responses=True,
    )


def _queue_depths() -> tuple[bool, str, dict[str, int]]:
    """Длина каждой очереди у брокера, в который Celery реально публикует."""
    url = get_settings().celery_broker_url
    if not url.startswith("redis"):
        # Брокер не Redis — длину очереди так не узнать, но это не отказ.
        return True, f"{mask_url(url)} (длина очередей доступна только для Redis)", {}
    try:
        client = _broker_client()
        depths = {queue: int(client.llen(queue)) for queue in KNOWN_QUEUES}
    except Exception as exc:  # noqa: BLE001 - диагностика не имеет права падать
        return False, f"брокер недоступен ({mask_url(url)}): {exc}", {}
    return True, f"отвечает ({mask_url(url)})", depths


def _inspect_workers() -> tuple[bool, str, dict[str, list[str]]]:
    """Что говорит сам worker: отвечает ли и какие очереди слушает."""
    try:
        from app.tasks.celery_app import celery_app

        inspector = celery_app.control.inspect(timeout=INSPECT_TIMEOUT_SECONDS)
        active = inspector.active_queues()
    except Exception as exc:  # noqa: BLE001
        return False, f"inspect не отработал: {exc}", {}
    if not active:
        return False, "ни один worker не ответил на inspect", {}
    consumed = {
        node: sorted({queue.get("name", "") for queue in queues if queue.get("name")})
        for node, queues in active.items()
    }
    return True, f"ответили worker'ы: {', '.join(sorted(consumed))}", consumed


def _publish_route() -> tuple[str, str]:
    """Куда на самом деле уйдёт задача конвейера: брокер и очередь.

    Отвечает на вопрос, который не виден ни по heartbeat, ни по `inspect`:
    сторож может исправно отправлять задачу не туда, где её ждёт worker, — и
    тогда всё выглядит здоровым, а пакет не двигается.
    """
    try:
        from app.tasks.celery_app import celery_app

        task_name = "app.tasks.pipeline_tasks.run_item_pipeline"
        route = celery_app.amqp.router.route({}, task_name)
        queue = route.get("queue")
        queue_name = getattr(queue, "name", queue) or celery_app.conf.task_default_queue
        return mask_url(celery_app.conf.broker_url or ""), str(queue_name)
    except Exception as exc:  # noqa: BLE001
        return f"не удалось определить: {exc}", ""


def _analyse(report: DoctorReport) -> None:
    """Заполняет verdict и hints — то, ради чего команда и нужна."""
    if report.eager:
        report.verdict = (
            "Задачи выполняются синхронно в API (CELERY_TASK_ALWAYS_EAGER=true) — "
            "отдельный worker не нужен."
        )
        return

    if not report.broker_ok:
        report.verdict = "Redis недоступен — задачи некуда складывать, конвейер стоит."
        report.hints.append(
            "Поднимите Redis: `docker compose up -d redis`, затем проверьте CELERY_BROKER_URL в .env."
        )
        return

    backlog = {q: n for q, n in report.queue_depths.items() if n > 0}

    # Worker не отвечает ни на inspect, ни heartbeat'ом — его просто нет.
    if not report.inspect_ok and not report.worker.alive:
        report.verdict = "Worker не запущен или не может стартовать — очередь разбирать некому."
        report.hints.append(
            "Смотрите, почему упал контейнер: `docker compose ps worker` и "
            "`docker compose logs worker --tail=60`."
        )
        report.hints.append("Поднять заново: `docker compose up -d worker`.")
        if backlog:
            report.hints.append(
                "Накопленное разберётся сторожем само; ускорить — `make run-pending`."
            )
        return

    # Worker отвечает на inspect, но heartbeat молчит — рассинхрон версий образа.
    if report.inspect_ok and not report.worker.alive:
        report.verdict = (
            "Worker жив и отвечает на inspect, но heartbeat в Redis не пишется — "
            "API считает его мёртвым и прогоняет пакеты синхронно."
        )
        report.hints.append(
            "Обычно это старый образ без сигнала worker_ready: пересоберите worker "
            "(`docker compose up -d --build worker`)."
        )

    # Самое коварное: worker живой, но слушает не те очереди.
    if report.inspect_ok:
        missing = {
            queue: [node for node, queues in report.consumed_queues.items() if queue not in queues]
            for queue in KNOWN_QUEUES
        }
        unheard = [queue for queue, nodes in missing.items() if len(nodes) == len(report.consumed_queues)]
        if unheard:
            report.verdict = (
                f"Очередь(и) {', '.join(unheard)} не слушает ни один worker — "
                "задачи туда уходят и остаются навсегда."
            )
            report.hints.append(
                "Проверьте CELERY_QUEUES в .env: worker должен слушать "
                f"`{','.join(KNOWN_QUEUES)}` (значение по умолчанию в backend/entrypoint.sh)."
            )
            return

    # Задача уходит в очередь, которую не слушает ни один ответивший worker.
    # Ни heartbeat, ни `inspect` такого не видят: оба «здоровы» по отдельности.
    if report.inspect_ok and report.publish_queue:
        listeners = [
            node for node, queues in report.consumed_queues.items()
            if report.publish_queue in queues
        ]
        if not listeners:
            report.verdict = (
                f"Задачи конвейера уходят в очередь `{report.publish_queue}`, "
                "но её не слушает ни один worker — пакет не сдвинется никогда."
            )
            report.hints.append(
                "Сверьте CELERY_QUEUES у worker'а с task_routes в "
                "app/tasks/celery_app.py — они разошлись."
            )
            return

    if report.stuck:
        # Пустые очереди при живом worker'е и висящем пакете — это не потерянное
        # сообщение: класть его было бы некуда. Значит, задачу никто не отправлял,
        # то есть сторож не делает проходы, хотя настройка включена.
        idle_broker = not backlog
        report.verdict = (
            f"Worker на связи, но {len(report.stuck)} пакет(ов) висят дольше порога — "
            + (
                "очереди при этом пусты, то есть задачу никто не переотправляет: "
                "похоже, сторож не делает проходы."
                if idle_broker
                else "сообщение потерялось либо пакет обрабатывается дольше ожидаемого."
            )
        )
        if idle_broker:
            report.hints.append(
                "Сторож живёт в процессе api, а эта команда запускается отдельным "
                "контейнером и его поток не видит. Проверьте, что он стартовал: "
                "`docker compose logs api | grep app.services.watchdog`."
            )
        report.hints.append(
            "Разобрать зависшее прямо сейчас — `make run-pending`. "
            "Если повторяется — ищите ошибку шага в `docker compose logs worker`."
        )
        return

    if not report.verdict:
        if backlog:
            report.verdict = (
                "Worker на связи и разбирает очередь; в очереди есть необработанные задачи — "
                "это нормально, если они не копятся от прогона к прогону."
            )
        else:
            report.verdict = "Очередь разбирается штатно: worker на связи, зависших пакетов нет."


def diagnose() -> DoctorReport:
    """Полный разбор состояния очереди."""
    from app.db.session import session_scope
    from app.services.watchdog import find_stuck

    settings = get_settings()
    status = worker_status()
    broker_ok, broker_detail, depths = _queue_depths()

    report = DoctorReport(
        worker=status,
        eager=settings.celery_task_always_eager,
        broker_ok=broker_ok,
        broker_detail=broker_detail,
        queue_depths=depths,
    )

    if not report.eager:
        report.publish_broker, report.publish_queue = _publish_route()
        report.inspect_ok, report.inspect_detail, report.consumed_queues = _inspect_workers()
        try:
            with session_scope() as session:
                report.stuck = find_stuck(session, include_running=not status.alive)
        except Exception as exc:  # noqa: BLE001 - без БД остальной отчёт всё ещё полезен
            report.hints.append(f"Не удалось опросить базу по зависшим пакетам: {exc}")

    _analyse(report)
    return report


def format_report(report: DoctorReport) -> str:
    """Отчёт в виде, пригодном для копирования целиком."""
    s = get_settings()
    lines = ["=== Диагностика очереди ==="]

    alive = "жив" if report.worker.alive else "НЕ ОТВЕЧАЕТ"
    lines.append(f"worker (heartbeat): {alive} — {report.worker.detail}")
    lines.append(f"брокер: {report.broker_detail}")

    if report.queue_depths:
        depths = ", ".join(f"{queue}={count}" for queue, count in report.queue_depths.items())
        lines.append(f"длина очередей: {depths}")

    if not report.eager:
        lines.append(
            f"задача конвейера уйдёт: очередь `{report.publish_queue}` "
            f"на {report.publish_broker}"
        )
        lines.append(f"inspect: {report.inspect_detail or 'не опрашивался'}")
        for node, queues in sorted(report.consumed_queues.items()):
            lines.append(f"  {node} слушает: {', '.join(queues) or '(ничего)'}")

    lines.append(
        f"зависших пакетов: {len(report.stuck)}"
        + (f" (id: {', '.join(str(i) for i in report.stuck[:20])})" if report.stuck else "")
    )
    # Настройка, а не факт: поток сторожа живёт в процессе api, и отсюда его не видно.
    lines.append(
        "сторож (по настройке): "
        + (
            f"включён, проход раз в {s.pipeline_watchdog_interval_seconds} с, "
            f"порог зависания {s.pipeline_stuck_after_seconds} с"
            if s.pipeline_watchdog_enabled
            else "выключен (PIPELINE_WATCHDOG_ENABLED=false)"
        )
    )

    lines.append("")
    lines.append(f"ВЫВОД: {report.verdict}")
    for hint in report.hints:
        lines.append(f"  → {hint}")
    return "\n".join(lines)
