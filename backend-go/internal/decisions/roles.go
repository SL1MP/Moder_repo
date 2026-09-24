package decisions

import (
	"context"
	"fmt"
	"strings"

	"moderation/internal/domain"
	"moderation/internal/pipeline"
)

// --------------------------------------------------------------------------- карантин

// ReleaseQuarantine снимает карантин: досрочно (решением DevSecOps) или по
// истечении срока (фоновой задачей).
//
// Карантин снят с ВЕРСИИ пакета — значит, и со всех, кто её заказал.
func (s *Service) ReleaseQuarantine(ctx context.Context, item *domain.RequestItem, early bool, comment string) (*Result, error) {
	legacyManualQuarantine := false
	if item.Status == "awaiting_security" {
		var err error
		legacyManualQuarantine, err = s.hasOpenBlocker(ctx, item, "quarantine")
		if err != nil {
			return nil, err
		}
	}
	if item.Status != "quarantined" && !legacyManualQuarantine {
		return nil, fmt.Errorf("%w: пакет не находится в карантине (текущий статус: %s)",
			ErrConflict, item.Status)
	}

	note := "Срок карантина истёк — проверка продолжена автоматически."
	if early {
		note = "Карантин снят досрочно решением DevSecOps — проверка продолжена."
	}
	if comment != "" {
		note += " " + comment
	}

	if err := s.Repo.ClearQuarantineUntil(ctx, item.PackageVersionID); err != nil {
		return nil, err
	}

	result := &Result{Item: item}
	// Возобновляем с шага лицензии: карантин (шаг 2) повторно выполнять
	// незачем — дата публикации не изменилась.
	siblings, notifications, err := s.applyToSiblings(ctx, item,
		[]string{"quarantined"}, "license", note, []string{"quarantine"})
	if err != nil {
		return nil, err
	}
	legacySiblings, legacyNotifications, err := s.releaseLegacyQuarantineSiblings(ctx, item, note)
	if err != nil {
		return nil, err
	}
	siblings = append(siblings, legacySiblings...)
	notifications = append(notifications, legacyNotifications...)
	result.Siblings = siblings
	result.Notifications = append(result.Notifications, notifications...)

	// Шаг карантина повторно не выполняется, поэтому блокировку снимаем явно —
	// иначе публикация ждала бы вечно.
	if _, err := s.clearBlocker(ctx, item, "quarantine", note); err != nil {
		return nil, err
	}
	result.Notifications = append(result.Notifications, Notification{
		RequestItemID: item.ID, Event: "quarantine_released", Message: note,
	})
	if err := s.resume(ctx, item, "license"); err != nil {
		return nil, err
	}
	return result, nil
}

// releaseLegacyQuarantineSiblings доводит снятие до заявок, записанных старой
// версией сервиса как awaiting_security. Одного статуса недостаточно: так же
// помечаются настоящие блокировки сканеров, поэтому обязательно проверяем,
// что открытым остался именно шаг quarantine.
func (s *Service) releaseLegacyQuarantineSiblings(
	ctx context.Context, item *domain.RequestItem, note string,
) ([]int64, []Notification, error) {
	siblings, err := s.siblingsAwaiting(ctx, item, "awaiting_security")
	if err != nil {
		return nil, nil, err
	}
	var ids []int64
	var notifications []Notification
	for i := range siblings {
		sibling := &siblings[i]
		open, err := s.hasOpenBlocker(ctx, sibling, "quarantine")
		if err != nil {
			return nil, nil, err
		}
		if !open {
			continue
		}
		if _, err := s.clearBlocker(ctx, sibling, "quarantine", note); err != nil {
			return nil, nil, err
		}
		notifications = append(notifications, Notification{
			RequestItemID: sibling.ID, Event: pipeline.EventDecisionMade, Message: note,
		})
		if err := s.resume(ctx, sibling, "license"); err != nil {
			return nil, nil, err
		}
		ids = append(ids, sibling.ID)
	}
	return ids, notifications, nil
}

// --------------------------------------------------------------------------- DevSecOps

// DecideSecurity — решение DevSecOps по пакету, остановленному на шаге
// уязвимостей или сканирования содержимого.
//
// Одобрение снимает обе блокировки по содержимому (vuln_scan, banner_scan):
// DevSecOps принимает решение по пакету целиком, а не по каждому сканеру
// отдельно. SAST в этот список не входит — он информационный (см.
// pipeline.SecurityBlockers).
func (s *Service) DecideSecurity(ctx context.Context, item *domain.RequestItem, approve bool, actorID int64, comment string) (*Result, error) {
	if item.Status != "awaiting_security" {
		return nil, fmt.Errorf("%w: пакет не ждёт решения DevSecOps (текущий статус: %s)",
			ErrConflict, item.Status)
	}
	if !approve && strings.TrimSpace(comment) == "" {
		return nil, fmt.Errorf("%w: при отклонении комментарий обязателен", ErrValidation)
	}

	result := &Result{Item: item}

	if approve {
		// Решение фиксируем на ВЕРСИИ пакета: иначе возобновлённый конвейер
		// снова упрётся в тот же вердикт сканера и вернёт пакет в очередь —
		// решение DevSecOps не имело бы эффекта.
		if err := s.Repo.SetSecurityOverride(ctx, item.PackageVersionID, actorID, comment); err != nil {
			return nil, err
		}
		note := fmt.Sprintf("DevSecOps разрешил публикацию: %s. Проверка продолжена.",
			commentOr(comment))

		// Разрешение записано на версии пакета — применяем ко всем заявкам с ней.
		siblings, notifications, err := s.applyToSiblings(ctx, item,
			[]string{"awaiting_security"}, "download", note, pipeline.SecurityBlockers)
		if err != nil {
			return nil, err
		}
		result.Siblings = siblings
		result.Notifications = append(result.Notifications, notifications...)

		for _, code := range pipeline.SecurityBlockers {
			if _, err := s.clearBlocker(ctx, item, code, note); err != nil {
				return nil, err
			}
		}
		result.Notifications = append(result.Notifications, Notification{
			RequestItemID: item.ID, Event: pipeline.EventDecisionMade, Message: note,
		})
		// Артефакт мог быть удалён из карантинной зоны при отклонении на шаге
		// уязвимостей — возобновляем со скачивания, чтобы его перекачать.
		if err := s.resume(ctx, item, "download"); err != nil {
			return nil, err
		}
		return result, nil
	}

	const nextAction = "Возьмите другую версию пакета или согласуйте замену с DevSecOps."
	note := "DevSecOps отклонил пакет: " + comment

	if err := s.Repo.FinishRequestItem(ctx, item.ID, "rejected", comment, nextAction, s.now()); err != nil {
		return nil, err
	}
	if err := s.Repo.UpdatePackageVersionStatus(ctx, item.PackageVersionID, "rejected", &comment); err != nil {
		return nil, err
	}
	item.Status = "rejected"

	siblings, notifications, err := s.rejectSiblings(ctx, item,
		[]string{"awaiting_security"}, comment, nextAction, note)
	if err != nil {
		return nil, err
	}
	result.Siblings = siblings
	result.Notifications = append(result.Notifications, notifications...)
	result.Notifications = append(result.Notifications, Notification{
		RequestItemID: item.ID, Event: pipeline.EventDecisionMade, Message: note,
	})
	return result, nil
}

// --------------------------------------------------------------------------- юрист

// DecideLicense — решение юриста по заявленной лицензии.
//
// Подтверждение возобновляет конвейер с шага скачивания: шаг лицензии повторно
// не выполняется, поэтому его блокировку снимаем явно.
func (s *Service) DecideLicense(ctx context.Context, item *domain.RequestItem, approve bool, actorID int64, spdxID, comment string) (*Result, error) {
	waiting := []string{"awaiting_legal", "license_claimed"}
	if !domain.Contains(waiting, item.Status) {
		return nil, fmt.Errorf("%w: пакет не ждёт решения юриста (текущий статус: %s)",
			ErrConflict, item.Status)
	}
	if !approve && strings.TrimSpace(comment) == "" {
		return nil, fmt.Errorf("%w: при отклонении комментарий обязателен", ErrValidation)
	}

	result := &Result{Item: item}

	if approve {
		if spdxID != "" {
			if err := s.Repo.SetVersionLicense(ctx, item.PackageVersionID, spdxID, "claim"); err != nil {
				return nil, err
			}
			// Подтверждённая лицензия предлагается для других версий этого
			// пакета.
			version, err := s.Repo.GetPackageVersion(ctx, item.PackageVersionID)
			if err != nil {
				return nil, err
			}
			if err := s.Repo.SetPackageConfirmedLicense(ctx, version.PackageID, spdxID, version.RawVersion); err != nil {
				return nil, err
			}
		}
		note := fmt.Sprintf("Юрист подтвердил лицензию %s — проверка продолжена со шага скачивания.",
			licenseOr(spdxID))

		// Лицензия подтверждена для ВЕРСИИ пакета: тот же пакет, заказанный в
		// другой заявке, обязан сдвинуться вместе с этим.
		siblings, notifications, err := s.applyToSiblings(ctx, item,
			waiting, "download", note, []string{"license"})
		if err != nil {
			return nil, err
		}
		result.Siblings = siblings
		result.Notifications = append(result.Notifications, notifications...)

		if _, err := s.clearBlocker(ctx, item, "license", note); err != nil {
			return nil, err
		}
		result.Notifications = append(result.Notifications, Notification{
			RequestItemID: item.ID, Event: pipeline.EventDecisionMade, Message: note,
		})
		if err := s.resume(ctx, item, "download"); err != nil {
			return nil, err
		}
		return result, nil
	}

	const nextAction = "Лицензия не согласована. Подберите пакет с разрешённой лицензией."
	note := "Юрист отклонил лицензию: " + comment

	if err := s.Repo.FinishRequestItem(ctx, item.ID, "rejected", comment, nextAction, s.now()); err != nil {
		return nil, err
	}
	if err := s.Repo.UpdatePackageVersionStatus(ctx, item.PackageVersionID, "rejected", &comment); err != nil {
		return nil, err
	}
	item.Status = "rejected"

	siblings, notifications, err := s.rejectSiblings(ctx, item, waiting, comment, nextAction, note)
	if err != nil {
		return nil, err
	}
	result.Siblings = siblings
	result.Notifications = append(result.Notifications, notifications...)
	result.Notifications = append(result.Notifications, Notification{
		RequestItemID: item.ID, Event: pipeline.EventDecisionMade, Message: note,
	})
	return result, nil
}

func commentOr(comment string) string {
	if strings.TrimSpace(comment) == "" {
		return "без комментария"
	}
	return comment
}

func licenseOr(spdx string) string {
	if spdx == "" {
		return "по ссылке"
	}
	return spdx
}
