package pipeline

import (
	"context"
	"fmt"

	"time"

	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Result — итог прогона конвейера.
type Result struct {
	// ItemStatus — статус, применённый к request_item.
	ItemStatus string
	// Blocked — конвейер остановился на непогашенном согласовании или
	// отклонении, а не дошёл до конца.
	Blocked bool
	// Terminal — пакет прошёл конвейер до конца (опубликован либо dry-run).
	Terminal bool
	// LastStep — код шага, на котором всё закончилось.
	LastStep string
	// Notifications — кого позвать. Отправку делает вызывающий код: у
	// конвейера нет своего канала доставки, и заводить его здесь значило бы
	// тащить в него транзакцию уведомлений.
	Notifications []Notification
}

// Notification — «позвать роль по поводу пакета».
type Notification struct {
	Event         string
	Roles         []string
	Message       string
	RequestItemID int64
}

// Run выполняет шаги конвейера начиная с fromCode (пусто — с шага 0) и
// сохраняет результат каждого шага.
//
// Проверка решения DevSecOps (security_override) делается ЗДЕСЬ, один раз, а
// не в каждом шаге сканирования: в Python-версии она продублирована трижды —
// отмеченный в architecture.md технический долг, который перенос исправляет.
// Смысл проверки: без неё возобновлённый после одобрения конвейер снова упёрся
// бы в тот же вердикт сканера и вернул пакет в очередь — решение DevSecOps не
// имело бы эффекта.
func Run(ctx context.Context, pc *Context, fromCode string) (Result, error) {
	startIdx := 0
	if fromCode != "" {
		idx, ok := domain.StepOrder[fromCode]
		if !ok {
			return Result{}, fmt.Errorf("неизвестный код шага %q", fromCode)
		}
		startIdx = idx
	}

	if err := pc.Deps.Validate(); err != nil {
		return Result{}, err
	}
	if err := loadSecurityOverride(ctx, pc); err != nil {
		return Result{}, err
	}

	r := pc.Deps.Repo
	result := Result{}

	// deferredStatus — статус от шага, который сам не остановил конвейер
	// (Defer), но которым нужно пометить пакет, если конвейер дойдёт до конца,
	// не встретив более приоритетной блокировки.
	deferredStatus := ""

	for i := startIdx; i < len(Steps); i++ {
		step := Steps[i]
		outcome, err := step.Run(ctx, pc)
		if err != nil {
			return result, fmt.Errorf("шаг %s: %w", step.Code(), err)
		}
		result.LastStep = step.Code()

		if err := saveStep(ctx, r, pc, step.Code(), outcome); err != nil {
			return result, err
		}

		if outcome.VersionStatus != "" {
			if err := r.UpdatePackageVersionQuarantine(
				ctx, pc.Version.ID, outcome.VersionStatus, pc.Version.QuarantineUntil); err != nil {
				return result, err
			}
			pc.Version.Status = outcome.VersionStatus
		}

		if outcome.NotifyEvent != "" {
			result.Notifications = append(result.Notifications, Notification{
				Event: outcome.NotifyEvent, Roles: outcome.NotifyRoles,
				Message: outcome.Message, RequestItemID: pc.Item.ID,
			})
		}

		if outcome.ItemStatus != "" {
			// Пишем сразу: карточка заявки должна показывать текущий
			// блокирующий статус, даже если конвейер после этого шага не
			// остановился. Более приоритетная блокировка перезапишет его на
			// следующей итерации.
			if err := applyItemStatus(ctx, r, pc, step.Code(), outcome); err != nil {
				return result, err
			}
			if outcome.Defer {
				deferredStatus = outcome.ItemStatus
			}
		}

		if outcome.Terminal {
			result.ItemStatus, result.Terminal = outcome.ItemStatus, true
			return result, nil
		}
		if outcome.Stop {
			result.ItemStatus, result.Blocked = outcome.ItemStatus, outcome.ItemStatus != ""
			return result, nil
		}
	}

	if deferredStatus != "" {
		result.ItemStatus, result.Blocked = deferredStatus, true
	}
	return result, nil
}

// loadSecurityOverride — одна проверка решения DevSecOps на весь прогон.
func loadSecurityOverride(ctx context.Context, pc *Context) error {
	pc.SecurityOverride = nil
	if pc.Version.SecurityOverrideAt == nil {
		return nil
	}
	who := "DevSecOps"
	if pc.Version.SecurityOverrideByID != nil {
		user, err := pc.Deps.Repo.GetUser(ctx, *pc.Version.SecurityOverrideByID)
		if err != nil {
			return err
		}
		who = repo.DisplayName(user, "DevSecOps")
	}
	pc.SecurityOverride = &Override{
		DecidedBy: who,
		DecidedAt: *pc.Version.SecurityOverrideAt,
		Comment:   deref(pc.Version.SecurityOverrideComment),
	}
	return nil
}

func saveStep(ctx context.Context, r *repo.Repo, pc *Context, code string, outcome StepOutcome) error {
	var message *string
	if outcome.Message != "" {
		message = &outcome.Message
	}
	now := pc.now()
	_, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
		RequestItemID: pc.Item.ID,
		StepCode:      code,
		StepOrder:     domain.StepOrder[code],
		Result:        outcome.Result,
		Message:       message,
		Details:       outcome.Details,
		StartedAt:     &now,
		FinishedAt:    &now,
	})
	if err != nil {
		return fmt.Errorf("сохранение результата шага %s: %w", code, err)
	}
	return nil
}

func applyItemStatus(ctx context.Context, r *repo.Repo, pc *Context, stepCode string, outcome StepOutcome) error {
	item := pc.Item
	item.Status = outcome.ItemStatus
	item.CurrentStep = &stepCode
	item.BlockedReason = nilIfEmpty(outcome.Message)
	item.NextAction = nilIfEmpty(outcome.NextAction)

	// waiting_since ставится, когда пакет впервые начал чего-то ждать: по нему
	// строится очередь ролей «кто ждёт дольше всех».
	var waitingSince *time.Time
	if domain.Contains(domain.ResumableStatuses, outcome.ItemStatus) {
		if item.WaitingSince != nil {
			waitingSince = item.WaitingSince
		} else {
			waitingSince = timePtr(pc.now())
		}
	}
	item.WaitingSince = waitingSince

	return r.UpdateRequestItemStatus(ctx, item.ID, outcome.ItemStatus,
		&stepCode, item.BlockedReason, item.NextAction, waitingSince)
}
