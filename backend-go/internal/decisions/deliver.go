package decisions

import (
	"context"
	"fmt"

	"moderation/internal/domain"
)

// Доставка последствий решения: уведомления автору и пересчёт статуса заявок.
//
// Живёт в пакете решений, а не в обработчике HTTP, потому что решение
// принимает не только человек: карантин снимает регламентная задача, и автор
// заявки обязан узнать об этом ровно так же, как если бы кнопку нажал
// DevSecOps. Две копии этой логики разъехались бы на первом же новом событии.

// Titles — заголовок уведомления по коду события.
var Titles = map[string]string{
	"decision_made":       "Принято решение по пакету",
	"quarantine_released": "Карантин снят",
	"package_approved":    "Пакет одобрен",
	"package_revoked":     "Пакет отозван",
	"license_claimed":     "Заявлена лицензия",
}

// Title — заголовок уведомления; неизвестное событие показывается кодом, а не
// пустой строкой: пустой заголовок в списке выглядит как сломанный сервис.
func Title(event string) string {
	if title, ok := Titles[event]; ok {
		return title
	}
	return event
}

// Deliver записывает уведомления и пересчитывает статусы задетых заявок.
//
// itemID передаётся отдельно от результата: статус заявки пересчитывается и
// тогда, когда решение не состоялось (конфликт, отказ) — пакет мог сменить
// состояние до отказа, и оставить свёртку заявки прежней значило бы показать
// людям неправду.
//
// Ошибки собираются, а не прерывают доставку: несозданное уведомление по
// одному пакету не повод оставить без уведомления остальные, а решение уже
// принято и откатывать его нельзя.
func (s *Service) Deliver(ctx context.Context, itemID int64, result *Result) []error {
	var errs []error
	if result == nil {
		return s.recompute(ctx, []int64{itemID})
	}

	for _, n := range result.Notifications {
		item, err := s.Repo.GetRequestItem(ctx, n.RequestItemID)
		if err != nil || item == nil {
			if err != nil {
				errs = append(errs, fmt.Errorf("уведомление по пакету #%d: %w", n.RequestItemID, err))
			}
			continue
		}
		request, err := s.Repo.GetModerationRequest(ctx, item.RequestID)
		if err != nil || request == nil {
			if err != nil {
				errs = append(errs, fmt.Errorf("уведомление по заявке #%d: %w", item.RequestID, err))
			}
			continue
		}
		requestID, itemID := request.ID, item.ID
		notification := domain.Notification{
			Event: n.Event, Title: Title(n.Event),
			RequestID: &requestID, RequestItemID: &itemID, CreatedAt: s.now(),
		}
		if n.Message != "" {
			body := n.Message
			notification.Body = &body
		}
		if _, err := s.Repo.InsertNotifications(ctx, []int64{request.AuthorID}, notification); err != nil {
			errs = append(errs, fmt.Errorf("уведомление по пакету #%d не создано: %w", itemID, err))
		}
	}

	touched := []int64{itemID}
	if result.Item != nil {
		touched = append(touched, result.Item.ID)
	}
	touched = append(touched, result.Siblings...)
	errs = append(errs, s.recompute(ctx, touched)...)
	return errs
}

// recompute пересчитывает свёртку статуса у всех заявок, задетых решением, —
// своей и чужих. Решение по версии пакета меняет состояние заявок, о которых
// нажавший кнопку не знает.
func (s *Service) recompute(ctx context.Context, touched []int64) []error {
	var errs []error
	seen := map[int64]bool{}
	for _, id := range touched {
		item, err := s.Repo.GetRequestItem(ctx, id)
		if err != nil || item == nil || seen[item.RequestID] {
			continue
		}
		seen[item.RequestID] = true
		if _, err := s.Repo.RecomputeRequestStatus(ctx, item.RequestID); err != nil {
			errs = append(errs, fmt.Errorf("статус заявки #%d не пересчитан: %w", item.RequestID, err))
		}
	}
	return errs
}
