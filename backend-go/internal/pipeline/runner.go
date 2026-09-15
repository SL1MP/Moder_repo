package pipeline

import (
	"context"
	"fmt"

	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Run выполняет шаги конвейера начиная с fromCode (пусто — с самого начала,
// шага 0) и сохраняет результат каждого шага. В отличие от Python-версии,
// где это делает Celery-таска, здесь — синхронный вызов; асинхронность
// (очередь) — фаза 6, см. docs/migration-to-go.md.
//
// Возвращает финальный статус, который нужно применить к RequestItem, и
// булев Blocked — остановился ли конвейер на блокирующем решении роли
// (в отличие от "закончились реализованные шаги", см. package doc).
type Result struct {
	ItemStatus string
	Blocked    bool
}

func Run(ctx context.Context, r *repo.Repo, item *domain.RequestItem, pc *Context, fromCode string) (Result, error) {
	startIdx := 0
	if fromCode != "" {
		idx, ok := domain.StepOrder[fromCode]
		if !ok {
			return Result{}, fmt.Errorf("неизвестный код шага %q", fromCode)
		}
		startIdx = idx
	}
	if startIdx >= len(Steps) {
		return Result{}, fmt.Errorf("шаг с индексом %d ещё не реализован (см. docs/migration-to-go.md)", startIdx)
	}

	// deferredStatus — статус от шага, который сам не остановил конвейер
	// (LicenseStep при warn, Stop=false), но которым нужно пометить item,
	// если конвейер дойдёт до конца РЕАЛИЗОВАННЫХ шагов, не встретив более
	// приоритетной блокировки. Аналог Python StepOutcome.defer, см. package
	// doc в steps.go.
	var deferredStatus string

	for i := startIdx; i < len(Steps); i++ {
		step := Steps[i]
		outcome, err := step.Run(ctx, pc)
		if err != nil {
			return Result{}, fmt.Errorf("шаг %s: %w", step.Code(), err)
		}

		var msg *string
		if outcome.Message != "" {
			msg = &outcome.Message
		}
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID,
			StepCode:      step.Code(),
			StepOrder:     domain.StepOrder[step.Code()],
			Result:        outcome.Result,
			Message:       msg,
		}); err != nil {
			return Result{}, fmt.Errorf("сохранение результата шага %s: %w", step.Code(), err)
		}

		if outcome.VersionStatus != "" {
			if err := r.UpdatePackageVersionQuarantine(ctx, pc.Version.ID, outcome.VersionStatus, pc.Version.QuarantineUntil); err != nil {
				return Result{}, err
			}
			pc.Version.Status = outcome.VersionStatus
		}

		if outcome.Stop {
			if outcome.ItemStatus != "" {
				if err := applyItemStatus(ctx, r, item, step.Code(), outcome); err != nil {
					return Result{}, err
				}
				return Result{ItemStatus: outcome.ItemStatus, Blocked: true}, nil
			}
			return Result{}, nil
		}

		if outcome.ItemStatus != "" {
			// Пишем в БД сразу — карточка заявки должна показывать текущий
			// блокирующий статус, даже если конвейер после этого шага не
			// остановился (LicenseStep). Если далее по конвейеру найдётся
			// более приоритетная блокировка, она перезапишет статус тем же
			// путём на следующей итерации.
			deferredStatus = outcome.ItemStatus
			if err := applyItemStatus(ctx, r, item, step.Code(), outcome); err != nil {
				return Result{}, err
			}
		}
	}

	if deferredStatus != "" {
		return Result{ItemStatus: deferredStatus, Blocked: true}, nil
	}
	return Result{}, nil
}

func applyItemStatus(ctx context.Context, r *repo.Repo, item *domain.RequestItem, stepCode string, outcome StepOutcome) error {
	msg := outcome.Message
	step := stepCode
	item.Status = outcome.ItemStatus
	item.BlockedReason = &msg
	item.CurrentStep = &step
	return r.UpdateRequestItemStatus(ctx, item.ID, outcome.ItemStatus, &step, &msg, nil, nil)
}
