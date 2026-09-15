"""Атомарный захват пакета заявки перед прогоном конвейера.

Конвейер по одному пакету могут запустить двое: Celery-worker (штатный путь) и
сторож в процессе API (когда worker молчит). Захват через UPDATE ... WHERE
status = 'queued' гарантирует, что выполнит ровно один из них: проигравший
получит rowcount = 0 и просто ничего не сделает.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, or_, update
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.models import RequestItem

# Во сколько раз дольше порога «зависания» должна молчать строка в статусе
# `running`, чтобы считаться брошенной упавшим процессом.
STALE_RUNNING_FACTOR = 3


def stale_running_seconds() -> int:
    from app.core.config import get_settings

    return get_settings().pipeline_stuck_after_seconds * STALE_RUNNING_FACTOR


def claim_item(session: Session, item_id: int, *, stale_running_after_seconds: int) -> bool:
    """Переводит пакет `queued` → `running`. True, если захват удался.

    Строки в статусе `running` перехватываются только если они не обновлялись
    дольше `stale_running_after_seconds`: это след процесса, который упал
    посреди прогона. Живой прогон обновляет строку на каждом шаге, поэтому
    отобрать его у работающего worker'а нельзя.
    """
    stale_before = utcnow() - timedelta(seconds=stale_running_after_seconds)
    result = session.execute(
        update(RequestItem)
        .where(
            RequestItem.id == item_id,
            or_(
                RequestItem.status == "queued",
                and_(RequestItem.status == "running", RequestItem.updated_at < stale_before),
            ),
        )
        .values(status="running", updated_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    session.commit()
    session.expire_all()  # ORM-объекты выше по стеку не должны видеть старый статус
    return bool(result.rowcount == 1)
