// Package maintenance — регламентные задачи сервиса: то, что должно
// происходить само, без нажатия кнопки. Порт backend/app/tasks/scheduled.py.
//
// Почему это отдельный пакет, а не «ещё пара функций в воркере». Каждая из
// задач — тихая: если она не выполняется, ничего не падает и никто не видит
// ошибки. Пакет с карантином просто стоит вечно, временное хранилище просто
// растёт. Такую работу нельзя размазывать по обработчикам — её надо держать в
// одном месте, покрывать тестами и уметь запускать руками командой.
package maintenance

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Service — регламентные задачи.
type Service struct {
	Repo *repo.Repo
	// Decisions снимает карантин тем же кодом, каким это делает DevSecOps
	// кнопкой: распространение на siblings, снятие блокировки и возобновление
	// конвейера — не то, что стоит повторять второй раз.
	Decisions *decisions.Service
	// Storage — временное хранилище (карантинная зона).
	Storage storage.Store
	Logger  *slog.Logger
	// Now подменяется в тестах.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// ReleaseExpiredQuarantine снимает карантин с пакетов, у которых вышел срок,
// и возобновляет их конвейер.
//
// Без этой задачи карантин — тупик: шаг ставит статус «в карантине до даты»,
// а дальше пакет не двигается сам никогда. Воркер подбирает только очередь, и
// наступление даты для него — не событие.
//
// Ошибка по одному пакету не прекращает обход: десять застрявших пакетов не
// должны зависеть от одного сломанного.
func (s *Service) ReleaseExpiredQuarantine(ctx context.Context) (int, error) {
	items, err := s.Repo.ExpiredQuarantineItems(ctx, s.now())
	if err != nil {
		return 0, err
	}
	released := 0
	for i := range items {
		// Строка перечитывается: снятие карантина распространяется на все
		// заявки с этой версией, поэтому к своей очереди пакет может подойти
		// уже снятым — выборка была сделана до того. Без перечитывания он
		// снимался бы второй раз и второй раз уходил в очередь.
		item, err := s.Repo.GetRequestItem(ctx, items[i].ID)
		if err != nil || item == nil || item.Status != "quarantined" {
			continue
		}
		result, err := s.Decisions.ReleaseQuarantine(ctx, item, false, "")
		if err != nil {
			// Пакет мог сменить статус между выборкой и снятием — это не сбой.
			s.logger().Warn("карантин не снят", "item", item.ID, "error", err)
			continue
		}
		for _, deliverErr := range s.Decisions.Deliver(ctx, item.ID, result) {
			s.logger().Warn("последствия снятия карантина", "item", item.ID, "error", deliverErr)
		}
		s.audit(ctx, "quarantine_released", "request_item", strconv.FormatInt(item.ID, 10),
			map[string]any{"reason": "срок карантина истёк"})
		released++
	}
	if released > 0 {
		s.logger().Info("карантин снят по истечении срока", "пакетов", released)
	}
	return released, nil
}

// CleanupOrphanObjects удаляет из временного хранилища объекты, которые
// зависли дольше ttl.
//
// Зависают они после прогонов, прерванных на середине: байты пакета уже
// скачаны, а до публикации или отказа дело не дошло. Карантинная зона —
// временная по замыслу, и если её не убирать, место кончится в самый неудобный
// момент.
//
// Строка в базе помечается удалённой ДАЖЕ если хранилище ответило ошибкой:
// иначе следующий прогон снова придёт за тем же объектом, и задача будет
// биться об него вечно. Ошибку при этом мы не проглатываем — она в логе.
func (s *Service) CleanupOrphanObjects(ctx context.Context, ttl time.Duration) (int, error) {
	if ttl <= 0 {
		return 0, fmt.Errorf("срок жизни объекта во временном хранилище не задан")
	}
	cutoff := s.now().Add(-ttl)
	artifacts, err := s.Repo.OrphanArtifacts(ctx, cutoff)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, artifact := range artifacts {
		if artifact.S3Key == nil || *artifact.S3Key == "" {
			continue
		}
		if err := s.Storage.Delete(ctx, *artifact.S3Key); err != nil {
			s.logger().Warn("объект не удалён из временного хранилища",
				"artifact", artifact.ID, "key", *artifact.S3Key, "error", err)
		} else {
			removed++
		}
		// keepStatus=true только для опубликованных: у них статус published
		// уже финальный, и затирать его на purged нельзя.
		keepStatus := artifact.Status == "published"
		if err := s.Repo.MarkArtifactPurged(ctx, artifact.ID, s.now(), keepStatus); err != nil {
			s.logger().Warn("артефакт не помечен удалённым", "artifact", artifact.ID, "error", err)
		}
	}
	if len(artifacts) > 0 {
		s.audit(ctx, "s3_orphans_cleaned", "artifact", "",
			map[string]any{"removed": removed, "candidates": len(artifacts),
				"older_than_hours": int(ttl.Hours())})
		s.logger().Info("временное хранилище очищено",
			"удалено", removed, "кандидатов", len(artifacts))
	}
	return removed, nil
}

// audit пишет запись журнала от имени сервиса. Актор — не человек, и это
// должно быть видно: source=task отличает регламентную работу от кнопки.
func (s *Service) audit(ctx context.Context, action, entityType, entityID string, value map[string]any) {
	entry := domain.AuditLog{
		ActorName: "Регламентная задача", Action: action, EntityType: entityType,
		NewValue: value, Source: "task", CreatedAt: s.now(),
	}
	if entityID != "" {
		entry.EntityID = &entityID
	}
	if err := s.Repo.InsertAuditLog(ctx, entry); err != nil {
		s.logger().Warn("запись журнала не создана", "action", action, "error", err)
	}
}
