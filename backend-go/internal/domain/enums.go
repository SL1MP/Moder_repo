// Порт backend/app/db/enums.py — источник истины для допустимых значений.
// Держать 1:1 с Python-версией, пока она не выведена из эксплуатации (см.
// docs/migration-to-go.md, открытый вопрос про судьбу backend/). Списки here и
// CHECK-ограничения в migrations/ — оба снимок соответствующей ревизии; при
// добавлении нового значения — новая миграция ПЛЮС правка здесь, не одно без
// другого (тот же урок, что в migrations/0004, см. её комментарий).
package domain

// ManagerCodes — поддерживаемые пакетные менеджеры. Держать 1:1 с
// CHECK-ограничением в migrations/0014: новый менеджер — новая миграция ПЛЮС
// правка здесь, не одно без другого.
//
// Порядок — тот, в котором менеджеры показываются в выпадающем списке
// интерфейса: сначала четыре самых ходовых, затем остальные по алфавиту,
// и последними два «не из реестра» (git и files).
var ManagerCodes = []string{
	"pypi", "npm", "go", "nuget",
	"conan", "docker", "luarocks", "maven", "php", "terraform",
	"git", "files",
}

// Roles — роли RBAC. auditor — целевая пятая роль, см. docs/auth.md; ещё не
// заведена в БД/CHECK-ограничениях, добавить вместе с реализацией.
var Roles = []string{"admin", "devsecops", "legal", "developer"}

// VersionStatuses — статус package_version.
var VersionStatuses = []string{
	"new",               // заведена, конвейер не запускался
	"checking",          // конвейер выполняется
	"quarantined",       // ждёт окончания карантина (шаг 2)
	"awaiting_legal",    // ждёт решения юристов (шаг 3)
	"license_claimed",   // разработчик заявил лицензию, ждёт юриста
	"awaiting_security", // ждёт решения DevSecOps (шаг 5)
	"approved",          // опубликована в артефактори
	"rejected",          // отклонена
	"revoked",           // отозвана (blacklist или новая CVE)
	"blacklisted",       // запрещена правилами blacklist
	"failed",            // техническая ошибка конвейера
}

// RequestStatuses — агрегированный статус moderation_request.
// Держать 1:1 с CHECK-ограничением в migrations/0011.
var RequestStatuses = []string{
	"pending", "awaiting_security", "awaiting_legal", "quarantined",
	"approved", "partially_approved", "dry_run", "rejected", "cancelled", "failed",
}

// ItemStatuses — статус request_item, гранулярнее RequestStatuses (см.
// docs/architecture.md, "request_item.status — более гранулярный...").
// dry_run — шаг публикации отработал в режиме ARTIFACT_DRY_RUN: обработка
// завершена, но публикации не было, и помечать пакет approved нельзя (иначе
// команда установки вела бы в никуда). Держать 1:1 с CHECK-ограничением в
// migrations/0011.
// cancelled — автор закрыл заявку, пакет больше не нужен.
var ItemStatuses = []string{
	"queued", "running", "quarantined", "awaiting_legal", "license_claimed",
	"awaiting_security", "approved", "dry_run", "rejected", "revoked", "blacklisted",
	"cancelled", "failed",
}

var RequestSources = []string{"api", "ui", "cli", "gitlab"}

var DependencyKinds = []string{"direct", "transitive"}

// StepCodes — порядок конвейера, индекс в срезе = StepOrder.
var StepCodes = []string{
	"db_check",     // шаг 0 — наличие в базе
	"blacklist",    // шаг 1
	"quarantine",   // шаг 2
	"license",      // шаг 3
	"download",     // шаг 4
	"vuln_scan",    // шаг 5 — уязвимости по снапшоту OSV
	"sandbox_scan", // шаг 6 — динамический анализ в песочнице
	"publish",      // шаг 7
}

// RetiredStepCodes — шаги, снятые с конвейера, но оставшиеся в истории.
//
// Они не выполняются и в StepCodes их нет, однако строки pipeline_step с этими
// кодами лежат в базе у каждой заявки, проверенной до снятия. Поэтому:
// CHECK-ограничение обязано их принимать (migrations/0013), StepTitles —
// называть по-человечески, а карточка заявки — показывать как есть. Удалить
// код из списка допустимых значений значило бы сломать чтение старых заявок.
//
// banner_scan (политические баннеры, YARA) и sast_scan (semgrep) сняты по
// решению пользователя «на данном этапе». Реализация обоих сохранена —
// pipeline.RetiredSteps, internal/scanners; возврат в строй это добавление
// шага обратно в Steps и StepCodes плюс миграция на CHECK.
var RetiredStepCodes = []string{"banner_scan", "sast_scan"}

// AllStepCodes — действующие и снятые коды вместе: то, что допустимо встретить
// в базе. Именно этот список, а не StepCodes, годится для проверки «знаем ли
// мы такой шаг» при чтении строки.
var AllStepCodes = append(append([]string{}, StepCodes...), RetiredStepCodes...)

// StepOrder — код шага -> порядковый номер, вычисляется из StepCodes один раз.
var StepOrder = buildStepOrder()

func buildStepOrder() map[string]int {
	m := make(map[string]int, len(StepCodes))
	for i, code := range StepCodes {
		m[code] = i
	}
	return m
}

// StepTitles — названия шагов, включая снятые: старые заявки обязаны читаться.
var StepTitles = map[string]string{
	"db_check":     "Проверка наличия в базе",
	"blacklist":    "Blacklist",
	"quarantine":   "Карантин",
	"license":      "Лицензия",
	"download":     "Скачивание артефакта",
	"vuln_scan":    "Проверка на уязвимости",
	"sandbox_scan": "Проверка в песочнице",
	"publish":      "Выгрузка в артефактори",
	// Снятые с конвейера — см. RetiredStepCodes.
	"banner_scan": "Политические баннеры (шаг снят)",
	"sast_scan":   "SAST-анализ (шаг снят)",
}

// StepResults — результаты шага. info — шаг выполнен, публикацию не блокирует,
// но сказать по нему есть что (так отдаёт результат SAST). Держать 1:1 с
// CHECK-ограничением в migrations/0010.
var StepResults = []string{"pending", "running", "pass", "info", "warn", "fail", "skipped"}

var ArtifactStatuses = []string{"downloaded", "scanned", "published", "purged", "failed"}

var ClaimStatuses = []string{"pending", "approved", "rejected"}

// ResumableStatuses — статусы, из которых конвейер возобновляется вручную или
// фоновой задачей.
var ResumableStatuses = []string{"quarantined", "awaiting_legal", "license_claimed", "awaiting_security"}

// PendingVersionStatuses — запись в базе есть, но пакет ещё не прошёл
// конвейер: ставить его нельзя.
var PendingVersionStatuses = []string{
	"new", "checking", "quarantined", "awaiting_legal", "license_claimed", "awaiting_security",
}

// BlockedVersionStatuses — пакет проверку не прошёл: ставить нельзя, нужна
// замена или решение роли.
var BlockedVersionStatuses = []string{"rejected", "blacklisted", "revoked", "failed"}

// CheckStates — состояния ответа POST /packages/check. Намеренно не совпадают
// со статусами версии: разработчику важен не внутренний статус, а можно ли уже
// ставить пакет.
var CheckStates = []string{"approved", "in_progress", "blocked", "not_found", "invalid_format"}

var StatusTitles = map[string]string{
	"new":                "Новый",
	"queued":             "В очереди",
	"checking":           "Проверяется",
	"running":            "Проверяется",
	"quarantined":        "Ждёт окончания карантина",
	"awaiting_legal":     "Ждёт юристов",
	"license_claimed":    "Лицензия заявлена",
	"awaiting_security":  "Ждёт DevSecOps",
	"approved":           "Одобрен",
	"partially_approved": "Одобрен частично",
	// dry_run — проверка прошла целиком, но публикации не было
	// (ARTIFACT_DRY_RUN). Название обязано это объяснять: без него в карточке
	// стоит непонятное «dry_run», а раньше такой пакет и вовсе ронял заявку
	// в «Отклонена» — см. migrations/0009.
	"dry_run":  "Проверен, публикация не выполнялась",
	"rejected": "Отклонён",
	// cancelled — автор закрыл заявку: пакеты больше не нужны. Отдельно от
	// rejected: то решение роли («нельзя»), а это отказ автора («уже не
	// нужно»), и в отчётности их путать нельзя.
	"cancelled":   "Отменено автором",
	"revoked":     "Отозван",
	"blacklisted": "Запрещён (blacklist)",
	"failed":      "Ошибка проверки",
	"pending":     "Проверяется",
}

// Contains — есть ли значение в списке допустимых (замена Python-паттерна
// "value in TUPLE").
func Contains(values []string, v string) bool {
	for _, item := range values {
		if item == v {
			return true
		}
	}
	return false
}
