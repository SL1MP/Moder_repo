package pipeline

import (
	"context"
	"fmt"
	"time"

	"moderation/internal/domain"
)

// Config — пороги конвейера. Целевой источник — БД/admin API (см.
// docs/configuration-model.md), не .env — здесь просто структура значений,
// откуда они берутся, решает вызывающий код.
type Config struct {
	QuarantineDays int
}

// Context — то, с чем работает шаг: пакет, версия, конфигурация. Пакетные
// менеджеры (проверка реестра), артефактори, сканеры — сознательно не здесь,
// шаги 0–3 в них не нуждаются (см. package doc).
type Context struct {
	Package *domain.Package
	Version *domain.PackageVersion
	Config  Config
	BL      BlacklistPolicy
	Lic     LicensePolicy
}

// Step — один шаг конвейера.
type Step interface {
	Code() string
	Run(ctx context.Context, pc *Context) (StepOutcome, error)
}

// Steps — порядок выполнения, индекс = domain.StepOrder[Code()]. Шаги 4–8
// (download/vuln_scan/banner_scan/sast_scan/publish) сюда не добавлены —
// см. package doc.
var Steps = []Step{
	DbCheckStep{},
	BlacklistStep{},
	QuarantineStep{},
	LicenseStep{},
}

// --------------------------------------------------------------------------- шаг 0
// DbCheckStep — порт DbCheckStep (steps.py). Три исхода: версия уже
// approved/blacklisted/revoked — терминально; иначе — pass, конвейер
// продолжается.
type DbCheckStep struct{}

func (DbCheckStep) Code() string { return "db_check" }

func (DbCheckStep) Run(_ context.Context, pc *Context) (StepOutcome, error) {
	switch pc.Version.Status {
	case "approved":
		return StepOutcome{
			Result: "pass", Stop: true, ItemStatus: "approved",
			Message: "Версия уже одобрена — заявка не требуется, отдаём ссылку и команду установки.",
		}, nil
	case "blacklisted":
		return StepOutcome{
			Result: "fail", Stop: true, ItemStatus: "blacklisted",
			Message: "Версия в чёрном списке — новая заявка не переоткрывает решение.",
		}, nil
	case "revoked":
		return StepOutcome{
			Result: "fail", Stop: true, ItemStatus: "revoked",
			Message: "Версия отозвана — новая заявка не переоткрывает решение.",
		}, nil
	default:
		return StepOutcome{Result: "pass"}, nil
	}
}

// --------------------------------------------------------------------------- шаг 1
// BlacklistStep — порт BlacklistStep. fail останавливает конвейер немедленно,
// пакет не скачивается (шаг 4 в этой ревизии всё равно не реализован).
type BlacklistStep struct{}

func (BlacklistStep) Code() string { return "blacklist" }

func (BlacklistStep) Run(_ context.Context, pc *Context) (StepOutcome, error) {
	if pc.BL == nil {
		return StepOutcome{Result: "pass"}, nil
	}
	rule := pc.BL.Find(pc.Package.Manager, pc.Package.Name, pc.Version.Version)
	if rule == nil {
		return StepOutcome{Result: "pass"}, nil
	}
	reason := rule.Reason
	if reason == "" {
		reason = "Пакет запрещён правилами blacklist"
	}
	return StepOutcome{
		Result: "fail", Stop: true, ItemStatus: "blacklisted", VersionStatus: "blacklisted",
		Message: reason,
	}, nil
}

// --------------------------------------------------------------------------- шаг 2
// QuarantineStep — порт QuarantineStep. Версия моложе Config.QuarantineDays —
// статус quarantined, конвейер останавливается до истечения срока или
// досрочного снятия DevSecOps (docs/flows.md, шаг 7 общего флоу).
//
// Поведение при отсутствующем PublishedAt НЕ сверено с Python-версией built
// (registry_metadata ещё не заполняется — плагины пакетных менеджеров не
// перенесены, фаза 3) — здесь пропускается как pass с пометкой в Message,
// а не блокируется; требует проверки, когда появится реальный источник
// published_at.
type QuarantineStep struct{}

func (QuarantineStep) Code() string { return "quarantine" }

func (QuarantineStep) Run(_ context.Context, pc *Context) (StepOutcome, error) {
	if pc.Version.PublishedAt == nil {
		return StepOutcome{
			Result:  "pass",
			Message: "Дата публикации неизвестна (метаданные реестра ещё не переносились) — карантин пропущен.",
		}, nil
	}
	days := pc.Config.QuarantineDays
	if days <= 0 {
		days = 14 // дефолт Python-версии (QUARANTINE_DAYS), см. .env.example
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	if pc.Version.PublishedAt.After(cutoff) {
		until := pc.Version.PublishedAt.AddDate(0, 0, days)
		pc.Version.QuarantineUntil = &until
		return StepOutcome{
			Result: "warn", Stop: true, ItemStatus: "quarantined", VersionStatus: "quarantined",
			Message: fmt.Sprintf(
				"Версия опубликована %s — младше %d дней, карантин до %s.",
				pc.Version.PublishedAt.Format("2006-01-02"), days, until.Format("2006-01-02"),
			),
		}, nil
	}
	return StepOutcome{Result: "pass"}, nil
}

// --------------------------------------------------------------------------- шаг 3
// LicenseStep — порт LicenseStep. Единственный шаг конвейера, чей warn НЕ
// останавливает конвейер (Stop=false даже при warn) — согласования юриста и
// DevSecOps идут параллельно, см. docs/architecture.md.
type LicenseStep struct{}

func (LicenseStep) Code() string { return "license" }

func (LicenseStep) Run(_ context.Context, pc *Context) (StepOutcome, error) {
	spdx := ""
	if pc.Version.LicenseSPDX != nil {
		spdx = *pc.Version.LicenseSPDX
	}
	if pc.Lic == nil || !pc.Lic.IsAllowed(spdx) {
		msg := "Лицензия не определена или не разрешена справочником — ждём подтверждения юриста."
		if spdx != "" {
			msg = fmt.Sprintf("Лицензия %q не разрешена справочником — ждём подтверждения юриста.", spdx)
		}
		return StepOutcome{
			Result: "warn", Stop: false, ItemStatus: "awaiting_legal", VersionStatus: "awaiting_legal",
			Message: msg,
		}, nil
	}
	return StepOutcome{Result: "pass"}, nil
}
