package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"moderation/internal/domain"
	"moderation/internal/metrics"
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
// Проверка решения DevSecOps (security_override) делается ЗДЕСЬ один раз и
// передаётся обязательному шагу песочницы. OSV теперь advisory и override не
// использует. Для песочницы override применяется только к полученному
// вердикту (например, ложному DANGEROUS), но не заменяет отсутствующий прогон.
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
		// После скачивания пять независимых операций выполняются одновременно:
		// лицензия, Dragon, OSV, песочница и формирование SBOM. Возобновление с
		// шага внутри группы запускает выбранный и все следующие проверки, как
		// прежде делал последовательный runner.
		parallelStart := domain.StepOrder["license"]
		parallelEnd := domain.StepOrder["sbom"]
		if i >= parallelStart && i <= parallelEnd {
			group, err := runParallelSteps(ctx, pc, Steps[i:parallelEnd+1])
			result.Notifications = append(result.Notifications, group.notifications...)
			if group.lastStep != "" {
				result.LastStep = group.lastStep
			}
			if group.deferredStatus != "" {
				deferredStatus = group.deferredStatus
			}
			if err != nil {
				return result, err
			}
			if group.hardStop {
				result.ItemStatus, result.Blocked = group.itemStatus, group.itemStatus != ""
				return result, nil
			}
			i = parallelEnd
			continue
		}
		step := Steps[i]
		startedAt := pc.now()
		if err := saveStepStarted(ctx, r, pc, step.Code(), startedAt); err != nil {
			return result, err
		}
		outcome, err := step.Run(ctx, pc)
		// API мог остановить пакет, пока внешний вызов шага был в работе.
		// Не позволяем уже полученному результату вернуть stopped/cancelled в
		// running/ожидание. Текущий pipeline_step маршрут остановки уже пометил
		// warn; worker потеряет владение строкой и завершит прогон.
		if fresh, readErr := r.GetRequestItem(ctx, pc.Item.ID); readErr != nil {
			return result, readErr
		} else if fresh != nil && domain.Contains([]string{"stopped", "cancelled"}, fresh.Status) {
			result.ItemStatus = fresh.Status
			result.Blocked = true
			return result, nil
		}
		// Метрику пишем и по упавшему шагу: прогон, оборвавшийся ошибкой, —
		// это тоже исход, и не видеть его на графике хуже всего. Результат
		// «error» в шкале pipeline_step.result отсутствует намеренно: там
		// записываются вердикты шага, а это авария выполнения.
		outcomeResult := outcome.Result
		if err != nil {
			outcomeResult = "error"
		}
		metrics.ObserveStep(step.Code(), outcomeResult, pc.Package.Manager,
			pc.now().Sub(startedAt).Seconds())
		if err != nil {
			failed := Fail(fmt.Sprintf("Техническая ошибка выполнения шага: %v", err))
			if saveErr := saveStep(ctx, r, pc, step.Code(), failed, startedAt); saveErr != nil {
				return result, fmt.Errorf("шаг %s: %v; результат ошибки не сохранён: %w",
					step.Code(), err, saveErr)
			}
			return result, fmt.Errorf("шаг %s: %w", step.Code(), err)
		}
		result.LastStep = step.Code()

		if err := saveStep(ctx, r, pc, step.Code(), outcome, startedAt); err != nil {
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
			result.Notifications = append(result.Notifications,
				notificationsForOutcome(outcome, pc.Item.ID)...)
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

type parallelResult struct {
	notifications []Notification
	lastStep       string
	deferredStatus string
	itemStatus     string
	hardStop       bool
}

type parallelExecution struct {
	step      Step
	startedAt time.Time
	outcome   StepOutcome
	err       error
}

func runParallelSteps(ctx context.Context, pc *Context, steps []Step) (parallelResult, error) {
	result := parallelResult{}
	if len(steps) == 0 {
		return result, nil
	}
	if err := pc.Deps.Repo.UpdateRequestItemCurrentStep(ctx, pc.Item.ID, steps[0].Code()); err != nil {
		return result, fmt.Errorf("сохранение начала параллельных проверок: %w", err)
	}
	executions := make([]parallelExecution, len(steps))
	for i, step := range steps {
		executions[i] = parallelExecution{step: step, startedAt: pc.now()}
		if err := saveStepStartedRecord(ctx, pc.Deps.Repo, pc, step.Code(), executions[i].startedAt); err != nil {
			return result, err
		}
	}

	var wg sync.WaitGroup
	for i := range executions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stepContext := cloneForParallel(pc)
			executions[i].outcome, executions[i].err = executions[i].step.Run(ctx, stepContext)
		}(i)
	}
	wg.Wait()

	if fresh, err := pc.Deps.Repo.GetRequestItem(ctx, pc.Item.ID); err != nil {
		return result, err
	} else if fresh != nil && domain.Contains([]string{"stopped", "cancelled"}, fresh.Status) {
		result.itemStatus, result.hardStop = fresh.Status, true
		return result, nil
	}

	var firstErr error
	for i := range executions {
		exec := &executions[i]
		outcomeResult := exec.outcome.Result
		if exec.err != nil {
			outcomeResult = "error"
		}
		metrics.ObserveStep(exec.step.Code(), outcomeResult, pc.Package.Manager,
			pc.now().Sub(exec.startedAt).Seconds())
		if exec.err != nil {
			failed := Fail(fmt.Sprintf("Техническая ошибка выполнения шага: %v", exec.err))
			if saveErr := saveStep(ctx, pc.Deps.Repo, pc, exec.step.Code(), failed, exec.startedAt); saveErr != nil {
				return result, fmt.Errorf("шаг %s: %v; результат ошибки не сохранён: %w",
					exec.step.Code(), exec.err, saveErr)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("шаг %s: %w", exec.step.Code(), exec.err)
			}
			continue
		}
		if err := saveStep(ctx, pc.Deps.Repo, pc, exec.step.Code(), exec.outcome, exec.startedAt); err != nil {
			return result, err
		}
		result.lastStep = exec.step.Code()
		if exec.outcome.NotifyEvent != "" {
			result.notifications = append(result.notifications,
				notificationsForOutcome(exec.outcome, pc.Item.ID)...)
		}
	}
	if firstErr != nil {
		return result, firstErr
	}

	// A policy rejection (for example a forbidden license) wins over pending
	// approvals. Sandbox warn/fail is not a hard stop here: it is an open
	// DevSecOps blocker, so the already generated SBOM can still be enriched
	// and sent before PublishStep records that publication is waiting.
	for i := range executions {
		exec := &executions[i]
		if exec.outcome.Stop && !IsOpenResult(exec.step.Code(), exec.outcome.Result) {
			if err := applyParallelStatus(ctx, pc, exec.step.Code(), exec.outcome); err != nil {
				return result, err
			}
			result.itemStatus, result.hardStop = exec.outcome.ItemStatus, true
			return result, nil
		}
	}
	byCode := make(map[string]parallelExecution, len(executions))
	for _, exec := range executions {
		byCode[exec.step.Code()] = exec
	}
	for _, code := range BlockerPriority {
		exec, ok := byCode[code]
		if !ok || !IsOpenResult(code, exec.outcome.Result) {
			continue
		}
		// The request item must remain running until the post-processing
		// barrier, but the shared package version may already expose why this
		// run cannot publish. Choose exactly one status using BlockerPriority;
		// otherwise concurrent license/sandbox outcomes would race and the
		// final value would depend on goroutine completion order.
		if exec.outcome.VersionStatus != "" {
			if err := pc.Deps.Repo.UpdatePackageVersionQuarantine(
				ctx, pc.Version.ID, exec.outcome.VersionStatus, pc.Version.QuarantineUntil); err != nil {
				return result, err
			}
			pc.Version.Status = exec.outcome.VersionStatus
		}
		// Пока барьер VuMana и PublishStep ещё выполняются, request_item обязан
		// оставаться running: heartbeat владеет строкой именно по этому статусу.
		// Итоговый статус выбранной блокировки применит PublishStep после всех
		// пост-проверок. Иначе долгий upload SBOM выглядел бы воркеру как
		// потерянная задача и сам отменял бы собственный context.
		result.deferredStatus = exec.outcome.ItemStatus
		break
	}
	return result, nil
}

func applyParallelStatus(ctx context.Context, pc *Context, code string, outcome StepOutcome) error {
	if outcome.VersionStatus != "" {
		if err := pc.Deps.Repo.UpdatePackageVersionQuarantine(
			ctx, pc.Version.ID, outcome.VersionStatus, pc.Version.QuarantineUntil); err != nil {
			return err
		}
		pc.Version.Status = outcome.VersionStatus
	}
	if outcome.ItemStatus != "" {
		return applyItemStatus(ctx, pc.Deps.Repo, pc, code, outcome)
	}
	return nil
}

func cloneForParallel(pc *Context) *Context {
	clone := *pc
	if pc.Package != nil {
		value := *pc.Package
		clone.Package = &value
	}
	if pc.Version != nil {
		value := *pc.Version
		clone.Version = &value
	}
	if pc.Item != nil {
		value := *pc.Item
		clone.Item = &value
	}
	if pc.Request != nil {
		value := *pc.Request
		clone.Request = &value
	}
	if pc.Author != nil {
		value := *pc.Author
		clone.Author = &value
	}
	return &clone
}

// notificationsForOutcome не смешивает роли в одном событии. Публикация
// может одновременно ждать лицензию и песочницу; раньше событие называлось по
// первой блокировке («ждёт DevSecOps»), но рассылалось и юристам. Теперь у
// каждой роли собственное корректно названное уведомление.
func notificationsForOutcome(outcome StepOutcome, itemID int64) []Notification {
	if len(outcome.NotifyRoles) <= 1 {
		return []Notification{{
			Event: outcome.NotifyEvent, Roles: outcome.NotifyRoles,
			Message: outcome.Message, RequestItemID: itemID,
		}}
	}
	out := make([]Notification, 0, len(outcome.NotifyRoles))
	for _, role := range outcome.NotifyRoles {
		event := outcome.NotifyEvent
		switch role {
		case "legal":
			event = EventAwaitsLegal
		case "devsecops":
			event = EventAwaitsSecurity
		}
		out = append(out, Notification{
			Event: event, Roles: []string{role}, Message: outcome.Message,
			RequestItemID: itemID,
		})
	}
	return out
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

func saveStepStarted(
	ctx context.Context, r *repo.Repo, pc *Context, code string, startedAt time.Time,
) error {
	if err := r.UpdateRequestItemCurrentStep(ctx, pc.Item.ID, code); err != nil {
		return fmt.Errorf("сохранение текущего шага %s: %w", code, err)
	}
	return saveStepStartedRecord(ctx, r, pc, code, startedAt)
}

func saveStepStartedRecord(
	ctx context.Context, r *repo.Repo, pc *Context, code string, startedAt time.Time,
) error {
	message := "Шаг выполняется. Для внешних проверок это может занять несколько минут."
	_, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
		RequestItemID: pc.Item.ID,
		StepCode:      code,
		StepOrder:     domain.StepOrder[code],
		Result:        "running",
		Message:       &message,
		StartedAt:     &startedAt,
	})
	if err != nil {
		return fmt.Errorf("сохранение начала шага %s: %w", code, err)
	}
	return nil
}

func saveStep(
	ctx context.Context, r *repo.Repo, pc *Context, code string, outcome StepOutcome,
	startedAt time.Time,
) error {
	var message *string
	if outcome.Message != "" {
		message = &outcome.Message
	}
	finishedAt := pc.now()
	_, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
		RequestItemID: pc.Item.ID,
		StepCode:      code,
		StepOrder:     domain.StepOrder[code],
		Result:        outcome.Result,
		Message:       message,
		Details:       outcome.Details,
		StartedAt:     &startedAt,
		FinishedAt:    &finishedAt,
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
