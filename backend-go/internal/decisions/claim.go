package decisions

import (
	"context"
	"fmt"
	"strings"

	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/repo"
)

// Заявление лицензии разработчиком.
//
// Порт backend/app/services/decisions.py::claim_license. Нужно там, где
// справочник лицензию не разрешил, а она на деле допустима: разработчик
// прикладывает ссылку на текст, юрист смотрит и решает.
//
// Ссылка не просто сохраняется — по ней снимается текст (internal/licensesnap),
// потому что ссылка через год может вести в никуда, а решение юриста принято
// по конкретному тексту, и предъявить надо именно его.

// ClaimInput — что нужно для заявления лицензии.
type ClaimInput struct {
	Item *domain.RequestItem
	// URL — ссылка на текст лицензии.
	URL string
	// SPDXID — необязателен: разработчик может не знать идентификатора и
	// просто приложить ссылку. Заданный проверяется по справочнику.
	SPDXID  string
	Comment string
	// Snapshot — снятый по ссылке текст. Пустой допустим: ссылка может быть
	// недоступна с машины сервиса, и это не повод отказывать в заявлении —
	// но юрист должен видеть, что текста нет.
	Snapshot  string
	ActorID   int64
	ActorName string
	Source    string
}

// ClaimResult — что получилось.
type ClaimResult struct {
	Claim *repo.ClaimRow
	Item  *domain.RequestItem
	// NotifyError — уведомление юристам не ушло. Не ошибка заявления: оно уже
	// записано, и юрист увидит его в своей очереди. Но администратор обязан
	// знать, что оповещения не работают.
	NotifyError error
}

// ClaimLicense принимает заявление лицензии.
func (s *Service) ClaimLicense(
	ctx context.Context, in ClaimInput, known LicenseCatalog,
) (*ClaimResult, error) {
	if in.Item == nil {
		return nil, fmt.Errorf("%w: не указан пакет заявки", ErrValidation)
	}
	url := strings.TrimSpace(in.URL)
	if url == "" {
		return nil, fmt.Errorf("%w: ссылка на текст лицензии обязательна", ErrValidation)
	}

	// Проверяем БЛОКИРОВКУ, а не статус. Согласования идут параллельно, и пока
	// лицензия у юриста, статусом пакета может быть более блокирующий
	// awaiting_security — по нему заявление ошибочно отклонялось бы.
	steps, err := s.Repo.ListStepsByItem(ctx, in.Item.ID)
	if err != nil {
		return nil, err
	}
	waiting := domain.Contains([]string{"awaiting_legal", "license_claimed"}, in.Item.Status)
	if !pipeline.IsBlockedBy(steps, "license") && !waiting {
		return nil, fmt.Errorf("%w: пакет не ждёт решения по лицензии (текущий статус: %s)",
			ErrConflict, in.Item.Status)
	}

	spdx := strings.TrimSpace(in.SPDXID)
	if spdx != "" && known != nil && !known.Knows(spdx) {
		// Только идентификатор из справочника. Ограничение стоит и в
		// интерфейсе (там выпадающий список), но проверка нужна и здесь: API
		// вызывают и мимо UI, а произвольная строка тихо ломает
		// автоматическую сверку лицензии на следующем прогоне конвейера.
		return nil, fmt.Errorf(
			"%w: SPDX-идентификатор «%s» отсутствует в справочнике. Известные: %s…",
			ErrValidation, spdx, strings.Join(known.KnownIDs(15), ", "))
	}

	claim := domain.LicenseClaim{
		PackageVersionID: in.Item.PackageVersionID,
		RequestItemID:    &in.Item.ID,
		ClaimedByID:      in.ActorID,
		URL:              url,
		Status:           "pending",
	}
	if spdx != "" {
		claim.SPDXID = &spdx
	}
	if comment := strings.TrimSpace(in.Comment); comment != "" {
		claim.Comment = &comment
	}
	if snapshot := strings.TrimSpace(in.Snapshot); snapshot != "" {
		now := s.now()
		claim.SnapshotText = &snapshot
		claim.SnapshotFetchedAt = &now
	}

	row, err := s.Repo.CreateLicenseClaim(ctx, claim)
	if err != nil {
		return nil, err
	}

	// Статус НЕ понижаем: если пакет ждёт ещё и DevSecOps, это важнее, и
	// «лицензия заявлена» скрыло бы более блокирующее ожидание.
	status := pipeline.StatusFromBlockers(steps, "license_claimed")
	if status == "awaiting_legal" {
		status = "license_claimed"
	}
	nextAction := "Лицензия заявлена, ожидается подтверждение юриста."
	if err := s.Repo.UpdateRequestItemStatus(ctx, in.Item.ID, status,
		in.Item.CurrentStep, in.Item.BlockedReason, &nextAction, in.Item.WaitingSince); err != nil {
		return nil, err
	}
	in.Item.Status = status
	if err := s.Repo.UpdatePackageVersionStatus(ctx, in.Item.PackageVersionID, status, nil); err != nil {
		return nil, err
	}

	// Зовём юристов, а не автора заявки: автор и есть тот, кто только что
	// приложил ссылку, и уведомлять его о собственном действии незачем.
	// Напрямую, а не через Result.Notifications: те уходят автору заявки.
	label := in.Item.RequestedName + " " + in.Item.RequestedVersion
	requestID, itemID := in.Item.RequestID, in.Item.ID
	body := fmt.Sprintf("%s приложил ссылку на лицензию пакета %s: %s", in.ActorName, label, url)
	notifyErr := s.notifyRoles(ctx, []string{"legal"}, domain.Notification{
		Event: pipeline.EventLicenseClaimed, Title: Title(pipeline.EventLicenseClaimed),
		Body: &body, RequestID: &requestID, RequestItemID: &itemID, CreatedAt: s.now(),
	})
	// Неотправленное уведомление не отменяет заявление: оно уже записано, и
	// юрист увидит его в своей очереди. Но и молчать нельзя — возвращаем
	// вызывающему, чтобы он записал это в лог.
	result := &ClaimResult{Claim: row, Item: in.Item}
	if notifyErr != nil {
		result.NotifyError = notifyErr
	}
	return result, nil
}

// LicenseCatalog — справочник SPDX, по которому проверяется заявленный
// идентификатор. Интерфейс, а не *policy.LicensePolicy: пакет решений не
// должен зависеть от того, откуда справочник взялся, и в тестах он подставной.
type LicenseCatalog interface {
	// Knows — есть ли такой идентификатор в справочнике. Именно «есть», а не
	// «разрешён»: разработчик заявляет и запрещённую лицензию — отказывает по
	// ней юрист, а не форма ввода.
	Knows(spdxID string) bool
	// KnownIDs — известные идентификаторы, не больше limit. Для сообщения об
	// ошибке: «выберите из известных» без списка ничем не помогает.
	KnownIDs(limit int) []string
}
