"""Допустимые значения перечислимых полей и их русские подписи."""

from __future__ import annotations

# Держать 1:1 с CHECK-ограничением в alembic 0009 / go-миграции 0014: новый
# менеджер — новая миграция ПЛЮС правка здесь, не одно без другого.
#
# Порядок — тот, в котором менеджеры показываются в выпадающем списке
# интерфейса: сначала четыре самых ходовых, затем остальные по алфавиту, и
# последними два «не из реестра» (git и files).
MANAGER_CODES: tuple[str, ...] = (
    "pypi",
    "npm",
    "go",
    "nuget",
    "conan",
    "docker",
    "luarocks",
    "maven",
    "php",
    "terraform",
    "git",
    "files",
)

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
    # dry_run выставляет go-версия: проверка прошла целиком, публикации не было
    # (ARTIFACT_DRY_RUN). Свёртка статусов здесь его не ставит — известное
    # расхождение, см. docs/migration-to-go.md; но читать и хранить такую
    # заявку python-версия обязана.
    "dry_run",
    "rejected",
    # cancelled — автор закрыл заявку: пакеты больше не нужны. Не rejected:
    # то решение роли («нельзя»), а это отказ автора («уже не нужно»).
    "cancelled",
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
    "dry_run",  # проверен целиком, публикации не было (ARTIFACT_DRY_RUN)
    "rejected",
    "revoked",
    "blacklisted",
    "cancelled",  # автор закрыл заявку: пакет больше не нужен
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
    "vuln_scan",  # шаг 5 — уязвимости по снапшоту OSV
    "sandbox_scan",  # шаг 6 — динамический анализ в песочнице
    "publish",  # шаг 7
)

# Шаги, снятые с конвейера, но оставшиеся в истории.
#
# Они не выполняются, и в STEP_CODES их нет, однако строки pipeline_step с этими
# кодами лежат в базе у каждой заявки, проверенной до снятия. Поэтому
# CHECK-ограничение обязано их принимать (alembic 0008), STEP_TITLES — называть
# по-человечески, а карточка заявки — показывать как есть. Удалить код из списка
# допустимых значений значило бы сломать чтение старых заявок.
RETIRED_STEP_CODES: tuple[str, ...] = ("banner_scan", "sast_scan")

# Действующие и снятые коды вместе: то, что допустимо встретить в базе.
ALL_STEP_CODES: tuple[str, ...] = STEP_CODES + RETIRED_STEP_CODES

STEP_ORDER: dict[str, int] = {code: i for i, code in enumerate(STEP_CODES)}

STEP_TITLES: dict[str, str] = {
    "db_check": "Проверка наличия в базе",
    "blacklist": "Blacklist",
    "quarantine": "Карантин",
    "license": "Лицензия",
    "download": "Скачивание артефакта",
    "vuln_scan": "Проверка на уязвимости",
    "sandbox_scan": "Проверка в песочнице",
    "publish": "Выгрузка в артефактори",
    # Снятые с конвейера — см. RETIRED_STEP_CODES.
    "banner_scan": "Политические баннеры (шаг снят)",
    "sast_scan": "SAST-анализ (шаг снят)",
}

# info — шаг выполнен, публикацию не блокирует, но сказать по нему есть что:
# так отдаёт результат SAST (см. app/pipeline/steps.py::SastScanStep). Отдельное
# значение, а не pass: «пройден» рядом с находками читается как «чисто».
STEP_RESULTS: tuple[str, ...] = ("pending", "pass", "info", "warn", "fail", "skipped")

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
