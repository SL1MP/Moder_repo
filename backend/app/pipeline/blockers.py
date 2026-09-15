"""Непогашенные согласования пакета.

Согласования идут параллельно: шаг «Лицензия», не пройденный автоматически, не
останавливает конвейер — пакет уходит на скачивание и проверку уязвимостей,
чтобы DevSecOps увидел его в своей очереди сразу, а не после решения юриста.
Публикация при этом не состоится, пока все блокировки не сняты.

Состояние блокировки не хранится отдельной сущностью: шаг считается
непогашенным, пока строка `pipeline_step` имеет результат `warn`. Снятие —
отметка шага пройденным. Так состояние остаётся в одном месте и сразу видно в
карточке заявки.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.models import RequestItem

# Какой роли принадлежит решение по каждому шагу. Порядок кортежа —
# по «блокирующей силе», он же используется в recompute_request_status.
BLOCKER_STATUS: dict[str, str] = {
    "vuln_scan": "awaiting_security",
    "banner_scan": "awaiting_security",
    "sast_scan": "awaiting_security",
    "license": "awaiting_legal",
    "quarantine": "quarantined",
}
BLOCKER_PRIORITY: tuple[str, ...] = (
    "vuln_scan",
    "banner_scan",
    "sast_scan",
    "license",
    "quarantine",
)

# Какие результаты шага означают «решение роли ещё не принято».
# У проверки уязвимостей таких два: `warn` — база устарела, `fail` — балл выше
# порога. Оба уходят к DevSecOps, а не отклоняют пакет сами по себе.
OPEN_RESULTS: dict[str, tuple[str, ...]] = {
    "vuln_scan": ("warn", "fail"),
    # Сканеры содержимого конвейер не останавливают: находка уходит DevSecOps
    # как `warn`, чтобы он увидел все срабатывания разом, а не по одному.
    "banner_scan": ("warn",),
    "sast_scan": ("warn",),
    "license": ("warn",),
    "quarantine": ("warn",),
}


# Кто выносит решение по шагу и как об этом сказать пользователю. Держим рядом
# с BLOCKER_STATUS: второй такой справочник в другом модуле уже приводил к
# падению конвейера при добавлении нового шага.
BLOCKER_ROLE: dict[str, str | None] = {
    "vuln_scan": "devsecops",
    "banner_scan": "devsecops",
    "sast_scan": "devsecops",
    "license": "legal",
    "quarantine": None,  # срок, а не решение роли
}
BLOCKER_WAITING_FOR: dict[str, str] = {
    "vuln_scan": "DevSecOps",
    "banner_scan": "DevSecOps",
    "sast_scan": "DevSecOps",
    "license": "юристов",
    "quarantine": "окончания карантина",
}


def pending_blockers(item: RequestItem) -> list[str]:
    """Шаги, ждущие решения роли, в порядке убывания блокирующей силы."""
    rows = {row.step_code: row for row in item.steps}
    return [
        code
        for code in BLOCKER_PRIORITY
        if rows.get(code) and rows[code].result in OPEN_RESULTS[code]
    ]


def clear_blocker(session: Session, item: RequestItem, code: str, message: str) -> bool:
    """Отмечает шаг пройденным после решения роли. False — снимать было нечего."""
    row = next((r for r in item.steps if r.step_code == code), None)
    if row is None or row.result not in OPEN_RESULTS.get(code, ("warn",)):
        return False
    row.result = "pass"
    row.message = message
    row.finished_at = utcnow()
    session.flush()
    return True


def is_blocked_by(item: RequestItem, code: str) -> bool:
    """Ждёт ли пакет решения по конкретному шагу."""
    return code in pending_blockers(item)


def status_from_blockers(item: RequestItem, default: str) -> str:
    """Статус пакета по самой блокирующей из непогашенных проверок.

    Статус у пакета один, а ждать он может двух решений сразу. Показываем самое
    блокирующее, чтобы статус не «слабел» при действиях по менее важному шагу:
    приложенная ссылка на лицензию не должна прятать то, что пакет ещё и у
    DevSecOps.
    """
    blockers = pending_blockers(item)
    return BLOCKER_STATUS[blockers[0]] if blockers else default
