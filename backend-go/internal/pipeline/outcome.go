// Package pipeline — конвейер проверок пакета. Порт
// backend/app/pipeline/{steps,runner,blockers}.py на Go, см. docs/migration-to-go.md.
//
// Девять шагов по порядку: db_check, blacklist, quarantine, license, download,
// vuln_scan, banner_scan, sast_scan, publish. Первый fail останавливает
// конвейер.
//
// Центральная механика — ПАРАЛЛЕЛЬНЫЕ СОГЛАСОВАНИЯ. Шаг, не пройденный
// автоматически, конвейер не обязательно останавливает: пакет уходит дальше на
// скачивание и сканирование, чтобы DevSecOps увидел его в своей очереди сразу,
// а не после решения юриста. Публикация не состоится, пока не сняты все
// блокировки. Отдельной сущности «блокировка» нет: шаг считается непогашенным,
// пока строка pipeline_step имеет результат warn (или fail у vuln_scan) —
// см. blockers.go. Из этой механики выведен SAST: он информационный, его
// результат публикацию не блокирует никогда.
//
// Одно сознательное отличие от Python-версии: проверка security_override_at
// там продублирована в каждом из трёх шагов сканирования (отмеченный в
// architecture.md технический долг). Здесь она сделана один раз, в runner,
// перед группой шагов сканирования — см. Run.
package pipeline

// StepOutcome — результат одного шага конвейера.
type StepOutcome struct {
	// Result — то, что пишется в pipeline_step.result:
	// pass | info | warn | fail.
	Result  string
	Message string
	Details map[string]any

	// Stop — останавливает ли шаг конвейер.
	Stop bool
	// Defer — шаг не пройден и требует решения роли, но конвейер продолжается:
	// следующие шаги выполняются, чтобы вторая роль увидела пакет в своей
	// очереди сразу, а не после решения первой.
	Defer bool
	// Terminal — шаг успешно завершил обработку (пакет одобрен и опубликован).
	Terminal bool

	// ItemStatus/VersionStatus — требуемый статус request_item/package_version
	// после этого шага. Пусто — статус не меняется.
	ItemStatus    string
	VersionStatus string

	// NextAction — блок «Что делать» для разработчика в карточке заявки.
	NextAction string
	// NotifyRoles — кого позвать. Уведомления отправляет runner, а не шаг.
	NotifyRoles []string
	NotifyEvent string
}

// Pass — шаг пройден, конвейер идёт дальше.
func Pass(message string) StepOutcome {
	return StepOutcome{Result: "pass", Message: message}
}

// Warn — шаг не пройден, конвейер останавливается и ждёт решения роли.
func Warn(message string) StepOutcome {
	return StepOutcome{Result: "warn", Message: message, Stop: true}
}

// Fail — шаг не пройден, конвейер останавливается.
func Fail(message string) StepOutcome {
	return StepOutcome{Result: "fail", Message: message, Stop: true}
}

// Pending — нужно решение роли, но конвейер идёт дальше: согласования
// параллельны. Ровно этим шаг «Лицензия» и шаги сканирования отличаются от
// остальных.
func Pending(message string) StepOutcome {
	return StepOutcome{Result: "warn", Message: message, Defer: true}
}

// Info — шаг выполнен, публикацию не блокирует, но сказать по нему есть что:
// находки сохранены и попали в отчёт.
//
// Отдельный результат, а не pass, потому что «пройден» рядом с четырьмя
// находками читается как «чисто». И не warn: warn означает непогашенное
// согласование (см. blockers.go), а информационный шаг ничьего решения не
// ждёт. Таким шагом сделан SAST: находки нужны для отчёта, а не для запрета.
func Info(message string) StepOutcome {
	return StepOutcome{Result: "info", Message: message}
}

// with-методы: шаги собирают исход цепочкой, чтобы не плодить конструкторы с
// десятком необязательных аргументов.

func (o StepOutcome) WithDetails(details map[string]any) StepOutcome {
	o.Details = details
	return o
}

func (o StepOutcome) WithStatus(item, version string) StepOutcome {
	o.ItemStatus, o.VersionStatus = item, version
	return o
}

func (o StepOutcome) WithNextAction(action string) StepOutcome {
	o.NextAction = action
	return o
}

func (o StepOutcome) WithNotify(event string, roles ...string) StepOutcome {
	o.NotifyEvent, o.NotifyRoles = event, roles
	return o
}

func (o StepOutcome) WithTerminal() StepOutcome {
	o.Terminal = true
	return o
}

// События уведомлений. Порт app/adapters/notifier.py::Event.
const (
	EventAwaitsLegal     = "request_awaits_legal"
	EventAwaitsSecurity  = "request_awaits_security"
	EventPackageApproved = "package_approved"
	EventDecisionMade    = "decision_made"
)
