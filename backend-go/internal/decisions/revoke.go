package decisions

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
)

// Отзыв уже одобренного пакета.
//
// Это единственное действие сервиса, которое отменяет ранее принятое решение,
// и потому оно обязано быть громким: пакет снимается с публикации, все заявки
// с этой версией переводятся в «отозван», DevSecOps и авторы получают
// уведомление, в журнале остаётся причина. Тихий отзыв хуже отсутствующего:
// разработчик продолжит ставить пакет из внутреннего репозитория и не узнает,
// почему он вдруг перестал существовать.

// RevokeInput — что нужно для отзыва.
type RevokeInput struct {
	// Version — версия пакета, которую отзываем.
	Version *domain.PackageVersion
	// Manager, Name, DisplayName — откуда снимать с публикации.
	Manager     string
	Name        string
	DisplayName string
	Reason      string
	// ActorID — кто отзывает. nil у регламентной задачи.
	ActorID   *int64
	ActorName string
	// Source — ui | api | task.
	Source string
	// Unpublish — снимать ли пакет с публикации в артефактори. false нужен
	// там, где артефактори недоступно: статус всё равно надо поменять, иначе
	// сервис показывает одобренным то, что уже отозвано.
	Unpublish bool
}

// RevokeResult — что получилось.
type RevokeResult struct {
	// Items — пакеты заявок, переведённые в «отозван».
	Items []int64
	// Unpublished — пакет снят с публикации.
	Unpublished bool
	// UnpublishError — артефактори не отдал пакет. Не ошибка отзыва: статус
	// уже изменён, но администратор обязан узнать, что копия могла остаться.
	UnpublishError error
	Notifications  []Notification
}

// RevokeVersion отзывает версию пакета.
func (s *Service) RevokeVersion(ctx context.Context, in RevokeInput, store artifactstore.Store) (*RevokeResult, error) {
	if in.Version == nil {
		return nil, fmt.Errorf("%w: не указана версия пакета", ErrValidation)
	}
	if in.Reason == "" {
		return nil, fmt.Errorf("%w: отзыв без причины не принимается", ErrValidation)
	}
	result := &RevokeResult{}
	now := s.now()
	previous := in.Version.Status

	if err := s.Repo.UpdatePackageVersionStatus(ctx, in.Version.ID, "revoked", &in.Reason); err != nil {
		return nil, err
	}
	in.Version.Status = "revoked"

	if in.Unpublish && store != nil {
		result.Unpublished, result.UnpublishError = s.unpublish(ctx, in, store)
	}

	// Заявки с этой версией. Отзыв относится ко всем: решение вынесено по
	// содержимому пакета, а не по конкретной заявке.
	items, err := s.Repo.ListItemsByPackageVersion(ctx, in.Version.ID)
	if err != nil {
		return nil, err
	}
	note := "Пакет отозван: " + in.Reason
	for i := range items {
		item := items[i]
		if item.Status != "approved" {
			continue
		}
		if err := s.Repo.FinishRequestItem(ctx, item.ID, "revoked", in.Reason,
			"Пакет отозван: перейдите на исправленную версию.", now); err != nil {
			return nil, err
		}
		result.Items = append(result.Items, item.ID)
		result.Notifications = append(result.Notifications, Notification{
			RequestItemID: item.ID, Event: "package_revoked", Message: note,
		})
	}

	entityID := strconv.FormatInt(in.Version.ID, 10)
	entry := domain.AuditLog{
		ActorID: in.ActorID, ActorName: valueOr(in.ActorName, "Регламентная задача"),
		Action: "package_revoked", EntityType: "package_version", EntityID: &entityID,
		OldValue: map[string]any{"status": previous},
		NewValue: map[string]any{"status": "revoked", "reason": in.Reason},
		Source:   valueOr(in.Source, "task"), Comment: &in.Reason, CreatedAt: now,
	}
	if err := s.Repo.InsertAuditLog(ctx, entry); err != nil {
		return nil, err
	}

	// DevSecOps узнаёт об отзыве всегда, даже если заявок с этой версией уже
	// не осталось: пакет лежал во внутреннем репозитории, и его исчезновение —
	// событие для тех, кто отвечает за безопасность.
	if err := s.notifyRoles(ctx, []string{"devsecops"}, domain.Notification{
		Event: "package_revoked", Title: Title("package_revoked"),
		Body:      strPtr(fmt.Sprintf("%s %s — %s", in.DisplayName, in.Version.RawVersion, in.Reason)),
		CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// unpublish снимает пакет с публикации и помечает артефакты убранными.
func (s *Service) unpublish(ctx context.Context, in RevokeInput, store artifactstore.Store) (bool, error) {
	artifacts, err := s.Repo.ListArtifacts(ctx, in.Version.ID)
	if err != nil {
		return false, err
	}
	removed := false
	for _, artifact := range artifacts {
		if artifact.NexusURL == nil || *artifact.NexusURL == "" {
			continue
		}
		target := artifactstore.Target{
			Repo: repoFromURL(*artifact.NexusURL), Manager: in.Manager,
			Name: in.Name, DisplayName: in.DisplayName,
			Version: in.Version.RawVersion, Filename: artifact.Filename,
		}
		ok, err := store.Delete(ctx, target)
		if err != nil {
			return removed, err
		}
		removed = removed || ok
		if err := s.Repo.SetArtifactStatus(ctx, artifact.ID, "purged"); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// repoFromURL достаёт имя репозитория из адреса опубликованного файла.
//
// Имя репозитория берётся из адреса, а не из настроек: пакет мог быть
// опубликован в другой репозиторий (настройки с тех пор поменяли), и удалять
// надо оттуда, куда клали, а не туда, куда кладут сейчас.
func repoFromURL(url string) string {
	const marker = "/repository/"
	if idx := strings.Index(url, marker); idx >= 0 {
		rest := url[idx+len(marker):]
		if slash := strings.Index(rest, "/"); slash > 0 {
			return rest[:slash]
		}
		return rest
	}
	// Artifactory: {base}/{repo}/{path}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if slash := strings.Index(trimmed, "/"); slash >= 0 {
		rest := trimmed[slash+1:]
		if next := strings.Index(rest, "/"); next > 0 {
			return rest[:next]
		}
		return rest
	}
	return ""
}

// notifyRoles рассылает уведомление всем, у кого есть хотя бы одна из ролей.
func (s *Service) notifyRoles(ctx context.Context, roles []string, n domain.Notification) error {
	userIDs, err := s.Repo.UserIDsByRoles(ctx, roles)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return nil
	}
	_, err = s.Repo.InsertNotifications(ctx, userIDs, n)
	return err
}

func valueOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
