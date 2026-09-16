package pipeline

import (
	"context"
	"fmt"
	"time"

	"moderation/internal/domain"
)

// Step — один шаг конвейера.
type Step interface {
	Code() string
	Run(ctx context.Context, pc *Context) (StepOutcome, error)
}

// Steps — порядок выполнения, индекс = domain.StepOrder[Code()].
var Steps = []Step{
	DbCheckStep{},
	BlacklistStep{},
	QuarantineStep{},
	LicenseStep{},
	DownloadStep{},
	VulnScanStep{},
	BannerScanStep,
	SastScanStep,
	PublishStep{},
}

// StepByCode — шаг по коду.
func StepByCode(code string) (Step, bool) {
	for _, step := range Steps {
		if step.Code() == code {
			return step, true
		}
	}
	return nil, false
}

// --------------------------------------------------------------------------- шаг 0
// DbCheckStep — три исхода: версия уже approved/blacklisted/revoked —
// терминально; иначе pass, конвейер продолжается.
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
		return Pass(""), nil
	}
}

// --------------------------------------------------------------------------- шаг 1
// BlacklistStep — fail останавливает конвейер немедленно, пакет наружу не
// скачивается.
type BlacklistStep struct{}

func (BlacklistStep) Code() string { return "blacklist" }

func (BlacklistStep) Run(_ context.Context, pc *Context) (StepOutcome, error) {
	if pc.BL == nil {
		return Pass(""), nil
	}
	// Не прочитанный файл правил — не «запрещать нечего». Мы не знаем, что
	// запрещено, и молча пропустить пакет здесь значит пустить в контур ровно
	// то, ради чего этот шаг и существует. Отдаём решение DevSecOps — тот же
	// принцип, что с неотработавшим сканером.
	if pc.BL.Failed() {
		return Warn("Правила blacklist не загружены — проверить запрет автоматически нельзя.").
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("DevSecOps: почините файл правил (BLACKLIST_FILE) и перезапустите проверку, "+
				"либо подтвердите пакет вручную.").
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}
	rule := pc.BL.Find(pc.Package.Manager, pc.Package.Name, pc.Version.Version)
	if rule == nil {
		return Pass(""), nil
	}
	reason := rule.Reason
	if reason == "" {
		reason = "Пакет запрещён правилами blacklist"
	}
	return Fail(reason).
		WithStatus("blacklisted", "blacklisted").
		WithNextAction("Подберите другой пакет: этот запрещён политикой."), nil
}

// --------------------------------------------------------------------------- шаг 2
// QuarantineStep — версия моложе Config.QuarantineDays ждёт истечения срока
// или досрочного снятия DevSecOps.
type QuarantineStep struct{}

func (QuarantineStep) Code() string { return "quarantine" }

func (QuarantineStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	published := pc.Version.PublishedAt
	if published == nil {
		// Дата публикации приходит из метаданных реестра. Если её ещё не
		// запрашивали (обычный случай: шаг 2 идёт до шага скачивания), берём
		// оттуда — иначе карантин молча считался бы пройденным для любой
		// свежей версии.
		meta, err := pc.Metadata(ctx)
		if err != nil {
			return Warn(fmt.Sprintf(
				"Дата публикации не получена из реестра (%v) — карантин проверить нельзя.", err)).
				WithStatus("awaiting_security", "awaiting_security").
				WithNextAction("Дождитесь решения DevSecOps: реестр не ответил, карантин вручную.").
				WithNotify(EventAwaitsSecurity, "devsecops"), nil
		}
		published = meta.PublishedAt
	}
	if published == nil {
		return Pass("Реестр не сообщил дату публикации — карантин пропущен."), nil
	}

	pc.Version.PublishedAt = published
	days := pc.Config.QuarantineDays
	if days <= 0 {
		days = 14 // дефолт Python-версии (QUARANTINE_DAYS), см. .env.example
	}
	cutoff := pc.now().AddDate(0, 0, -days)
	if published.After(cutoff) {
		until := published.AddDate(0, 0, days)
		pc.Version.QuarantineUntil = &until
		return Warn(fmt.Sprintf(
			"Версия опубликована %s — младше %d дней, карантин до %s.",
			published.Format("2006-01-02"), days, until.Format("2006-01-02"))).
			WithStatus("quarantined", "quarantined").
			WithNextAction(fmt.Sprintf(
				"Дождитесь %s либо попросите DevSecOps снять карантин досрочно.",
				until.Format("2006-01-02"))), nil
	}
	return Pass(""), nil
}

// --------------------------------------------------------------------------- шаг 3
// LicenseStep — единственный из первых четырёх, чей warn НЕ останавливает
// конвейер: согласования юриста и DevSecOps идут параллельно.
type LicenseStep struct{}

func (LicenseStep) Code() string { return "license" }

func (LicenseStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	spdx := ""
	if pc.Version.LicenseSPDX != nil {
		spdx = *pc.Version.LicenseSPDX
	}
	// Лицензии ещё нет в базе — берём из метаданных реестра.
	if spdx == "" {
		if meta, err := pc.Metadata(ctx); err == nil && meta.LicenseSPDX != "" {
			spdx = meta.LicenseSPDX
			pc.Version.LicenseSPDX = &spdx
			source := "registry"
			pc.Version.LicenseSource = &source
		}
	}

	if pc.Lic != nil && pc.Lic.IsAllowed(spdx) {
		return Pass(fmt.Sprintf("Лицензия %s разрешена справочником.", spdx)), nil
	}

	message := "Лицензия не определена — ждём подтверждения юриста."
	switch {
	// Не загрузившийся справочник запрещает всё, и юрист обязан видеть
	// настоящую причину: иначе «лицензия не разрешена» про MIT выглядит как
	// ошибка сервиса, и её идут искать не там.
	case pc.Lic != nil && pc.Lic.Failed():
		message = "Справочник лицензий не загружен — проверить лицензию автоматически нельзя."
		if spdx != "" {
			message = fmt.Sprintf(
				"Справочник лицензий не загружен — лицензию %q проверить автоматически нельзя.", spdx)
		}
	case spdx != "":
		message = fmt.Sprintf("Лицензия %q не разрешена справочником — ждём подтверждения юриста.", spdx)
	}
	return Pending(message).
		WithDetails(map[string]any{"spdx": spdx}).
		WithStatus("awaiting_legal", "awaiting_legal").
		WithNextAction(
			"Приложите ссылку на файл лицензии или страницу проекта в карточке пакета — "+
				"заявка уйдёт юристам. Проверка на уязвимости идёт параллельно.").
		WithNotify(EventAwaitsLegal, "legal"), nil
}

// --------------------------------------------------------------------------- вспомогательное

// purgeArtifact удаляет объект из карантинной зоны и фиксирует время удаления.
// keepStatus=true — объект удалён после успешной публикации, это штатная
// уборка, а не «purged».
func purgeArtifact(ctx context.Context, pc *Context, artifact *domain.Artifact, keepStatus bool) error {
	if artifact == nil || artifact.S3Key == nil || *artifact.S3Key == "" || artifact.S3DeletedAt != nil {
		return nil
	}
	if err := pc.Deps.Storage.Delete(ctx, *artifact.S3Key); err != nil {
		return fmt.Errorf("удаление объекта из временного хранилища: %w", err)
	}
	now := pc.now()
	if err := pc.Deps.Repo.MarkArtifactPurged(ctx, artifact.ID, now, keepStatus); err != nil {
		return err
	}
	artifact.S3DeletedAt = &now
	pc.DropPayload()
	return nil
}

func ptr[T any](v T) *T { return &v }

func timePtr(t time.Time) *time.Time { return &t }
