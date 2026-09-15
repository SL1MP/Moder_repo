"""Допустимые значения перечислимых полей и их русские подписи."""

from __future__ import annotations

MANAGER_CODES: tuple[str, ...] = ("pypi", "npm", "go", "nuget")

ROLES: tuple[str, ...] = ("admin", "devsecops", "legal", "developer")

# Статус версии пакета в базе.
VERSION_STATUSES: tuple[str, ...] = (
    "new",  # заведена, конвейер не запускался
    "checking",  # конвейер выполняется
    "quarantined",  # ждёт окончания карантина (шаг 2)
    "awaiting_legal",  # ждёт решения юристов (шаг 3)
    "license_claimed",  # разработчик заявил лицензию, ждёт юриста
    "awaiting_security",  # ждёт решения DevSecOps (шаг 5)
    "approved",  # опубликована в артефактори
    "rejected",  # отклонена
    "revoked",  # отозвана (blacklist или новая CVE)
    "blacklisted",  # запрещена правилами blacklist
    "failed",  # техническая ошибка конвейера
)

REQUEST_STATUSES: tuple[str, ...] = (
    "pending",  # конвейер выполняется
    "awaiting_security",
    "awaiting_legal",
    "quarantined",
    "approved",  # все пакеты одобрены
    "partially_approved",
    "rejected",
    "failed",
)

ITEM_STATUSES: tuple[str, ...] = (
    "queued",
    "running",
    "quarantined",
    "awaiting_legal",
    "license_claimed",
    "awaiting_security",
    "approved",
    "rejected",
    "revoked",
    "blacklisted",
    "failed",
)

REQUEST_SOURCES: tuple[str, ...] = ("api", "ui", "cli", "gitlab")

DEPENDENCY_KINDS: tuple[str, ...] = ("direct", "transitive")

STEP_CODES: tuple[str, ...] = (
    "db_check",  # шаг 0 — наличие в базе
    "blacklist",  # шаг 1
    "quarantine",  # шаг 2
    "license",  # шаг 3
    "download",  # шаг 4
    "vuln_scan",  # шаг 5
    "banner_scan",  # шаг 6 — политические баннеры (YARA)
    "sast_scan",  # шаг 7 — SAST по исходникам пакета
    "publish",  # шаг 8
)

STEP_ORDER: dict[str, int] = {code: i for i, code in enumerate(STEP_CODES)}

STEP_TITLES: dict[str, str] = {
    "db_check": "Проверка наличия в базе",
    "blacklist": "Blacklist",
    "quarantine": "Карантин",
    "license": "Лицензия",
    "download": "Скачивание артефакта",
    "vuln_scan": "Проверка на уязвимости",
    "banner_scan": "Политические баннеры",
    "sast_scan": "SAST-анализ",
    "publish": "Выгрузка в артефактори",
}

STEP_RESULTS: tuple[str, ...] = ("pending", "pass", "warn", "fail", "skipped")

ARTIFACT_STATUSES: tuple[str, ...] = ("downloaded", "scanned", "published", "purged", "failed")

CLAIM_STATUSES: tuple[str, ...] = ("pending", "approved", "rejected")

# Статусы, из которых конвейер возобновляется вручную или фоновой задачей.
RESUMABLE_STATUSES: tuple[str, ...] = (
    "quarantined",
    "awaiting_legal",
    "license_claimed",
    "awaiting_security",
)

# Запись в базе есть, но пакет ещё не прошёл конвейер: ставить его нельзя.
PENDING_VERSION_STATUSES: tuple[str, ...] = (
    "new",
    "checking",
    "quarantined",
    "awaiting_legal",
    "license_claimed",
    "awaiting_security",
)

# Пакет проверку не прошёл: ставить нельзя, нужна замена или решение роли.
BLOCKED_VERSION_STATUSES: tuple[str, ...] = (
    "rejected",
    "blacklisted",
    "revoked",
    "failed",
)

# Состояния ответа `POST /packages/check` — что разработчику делать с записью.
# Намеренно не совпадают со статусами версии: разработчику важен не внутренний
# статус, а можно ли уже ставить пакет.
CHECK_STATES: tuple[str, ...] = (
    "approved",  # одобрен, есть команда установки
    "in_progress",  # заявка уже есть, идёт проверка — ждать, повторно не заводить
    "blocked",  # проверку не прошёл, нужна замена
    "not_found",  # в базе нет, нужно заводить заявку
    "invalid_format",
)

STATUS_TITLES: dict[str, str] = {
    "new": "Новый",
    "queued": "В очереди",
    "checking": "Проверяется",
    "running": "Проверяется",
    "quarantined": "Ждёт окончания карантина",
    "awaiting_legal": "Ждёт юристов",
    "license_claimed": "Лицензия заявлена",
    "awaiting_security": "Ждёт DevSecOps",
    "approved": "Одобрен",
    "partially_approved": "Одобрен частично",
    "rejected": "Отклонён",
    "revoked": "Отозван",
    "blacklisted": "Запрещён (blacklist)",
    "failed": "Ошибка проверки",
    "pending": "Проверяется",
}
