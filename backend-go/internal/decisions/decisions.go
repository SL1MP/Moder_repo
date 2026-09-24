// Package decisions — решения ролей по пакету: снятие карантина, вердикт
// DevSecOps, вердикт юриста. Порт backend/app/services/decisions.py.
//
// САМАЯ ВАЖНАЯ ЧАСТЬ ЭТОГО ПАКЕТА — РАСПРОСТРАНЕНИЕ НА SIBLINGS.
//
// Решение роли выносится по ВЕРСИИ ПАКЕТА, а не по заявке: подтверждённая
// лицензия, разрешение DevSecOps и снятие карантина пишутся в package_version
// и относятся ко всем, кто заказал эту версию. Один package_version живёт в
// заявках разных людей. Если возобновлять только тот request_item, из которого
// пришло решение, одинаковый пакет в чужой заявке останется заблокированным
// навсегда, хотя вердикт для него уже вынесен.
//
// Это самое незаметное для тестов поведение, если писать тесты «по одной
// заявке за раз» (прямое предупреждение в docs/migration-to-go.md). Поэтому
// оно покрыто тестами первым делом, а не в конце.
package decisions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/repo"
)

// Ошибки решений. Различаются по типу, а не по тексту: API отображает их в
// разные HTTP-коды (409 против 400).
var (
	// ErrConflict — пакет не в том состоянии, в котором такое решение возможно.
	ErrConflict = errors.New("пакет не ждёт этого решения")
	// ErrValidation — решение сформулировано неверно (например, отклонение без
	// комментария).
	ErrValidation = errors.New("решение сформулировано неверно")
)

// Service — решения ролей.
type Service struct {
	Repo *repo.Repo
	// Resume возобновляет конвейер с указанного шага. Отдельной функцией, а не
	// прямым вызовом pipeline.Run: в бою возобновление уходит в очередь, а в
	// тестах выполняется синхронно, и пакет решений не должен знать, как
	// именно.
	Resume ResumeFunc
	// Now подменяется в тестах.
	Now func() time.Time
}

// ResumeFunc — возобновление конвейера по пакету заявки, начиная с шага
// fromStep.
type ResumeFunc func(ctx context.Context, item *domain.RequestItem, fromStep string) error

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Result — что изменилось.
type Result struct {
	Item *domain.RequestItem
	// Siblings — пакеты той же версии в ДРУГИХ заявках, до которых доведено
	// решение. Возвращается наружу, чтобы вызывающий код мог показать
	// «решение применено к N заявкам» и чтобы это было видно в тестах.
	Siblings []int64
	// Notifications — кого уведомить; отправку делает вызывающий код.
	Notifications []Notification
}

// Notification — уведомление об изменении по пакету заявки.
type Notification struct {
	RequestItemID int64
	Event         string
	Message       string
}

// siblingsAwaiting — пакеты той же версии в других заявках, ждущие того же
// решения.
func (s *Service) siblingsAwaiting(ctx context.Context, item *domain.RequestItem, statuses ...string) ([]domain.RequestItem, error) {
	all, err := s.Repo.ListItemsByPackageVersion(ctx, item.PackageVersionID)
	if err != nil {
		return nil, err
	}
	var out []domain.RequestItem
	for _, candidate := range all {
		if candidate.ID == item.ID {
			continue
		}
		if domain.Contains(statuses, candidate.Status) {
			out = append(out, candidate)
		}
	}
	return out, nil
}

// applyToSiblings доводит решение до тех же пакетов в других заявках:
// снимает у них те же блокировки и возобновляет конвейер.
func (s *Service) applyToSiblings(
	ctx context.Context, item *domain.RequestItem, statuses []string,
	fromStep, note string, clearSteps []string,
) ([]int64, []Notification, error) {
	siblings, err := s.siblingsAwaiting(ctx, item, statuses...)
	if err != nil {
		return nil, nil, err
	}
	var ids []int64
	var notifications []Notification
	for i := range siblings {
		sibling := &siblings[i]
		for _, code := range clearSteps {
			if _, err := s.clearBlocker(ctx, sibling, code, note); err != nil {
				return nil, nil, err
			}
		}
		notifications = append(notifications, Notification{
			RequestItemID: sibling.ID, Event: pipeline.EventDecisionMade, Message: note,
		})
		if err := s.resume(ctx, sibling, fromStep); err != nil {
			return nil, nil, err
		}
		ids = append(ids, sibling.ID)
	}
	return ids, notifications, nil
}

// rejectSiblings — отклонение тоже относится ко всем, кто заказал эту версию.
func (s *Service) rejectSiblings(
	ctx context.Context, item *domain.RequestItem, statuses []string,
	comment, nextAction, note string,
) ([]int64, []Notification, error) {
	siblings, err := s.siblingsAwaiting(ctx, item, statuses...)
	if err != nil {
		return nil, nil, err
	}
	var ids []int64
	var notifications []Notification
	for i := range siblings {
		sibling := &siblings[i]
		if err := s.Repo.FinishRequestItem(ctx, sibling.ID, "rejected",
			comment, nextAction, s.now()); err != nil {
			return nil, nil, err
		}
		notifications = append(notifications, Notification{
			RequestItemID: sibling.ID, Event: pipeline.EventDecisionMade, Message: note,
		})
		ids = append(ids, sibling.ID)
	}
	return ids, notifications, nil
}

// clearBlocker отмечает шаг пройденным после решения роли. false — снимать
// было нечего.
//
// Отдельной сущности «блокировка» нет: шаг считается непогашенным, пока
// строка pipeline_step имеет результат из pipeline.OpenResults. Снятие —
// отметка шага пройденным.
func (s *Service) clearBlocker(ctx context.Context, item *domain.RequestItem, code, message string) (bool, error) {
	steps, err := s.Repo.ListStepsByItem(ctx, item.ID)
	if err != nil {
		return false, err
	}
	for _, step := range steps {
		if step.StepCode != code {
			continue
		}
		if !pipeline.IsOpenResult(code, step.Result) {
			return false, nil
		}
		if err := s.Repo.MarkStepPassed(ctx, item.ID, code, message, s.now()); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// hasOpenBlocker проверяет блокировку без изменения. Нужен для совместимости
// с пакетами, созданными до исправления статуса ручного карантина: у них
// request_item.status уже записан как awaiting_security, но открытым шагом
// остаётся именно quarantine.
func (s *Service) hasOpenBlocker(ctx context.Context, item *domain.RequestItem, code string) (bool, error) {
	steps, err := s.Repo.ListStepsByItem(ctx, item.ID)
	if err != nil {
		return false, err
	}
	for _, step := range steps {
		if step.StepCode == code && pipeline.IsOpenResult(code, step.Result) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) resume(ctx context.Context, item *domain.RequestItem, fromStep string) error {
	if s.Resume == nil {
		return fmt.Errorf("возобновление конвейера не настроено (Service.Resume)")
	}
	return s.Resume(ctx, item, fromStep)
}
