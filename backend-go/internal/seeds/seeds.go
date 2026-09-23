// Package seeds — первичное заполнение: справочники, демо-стенд, разовый
// импорт существующих списков пакетов. Порт backend/app/services/seeds.py.
//
// Почему отдельный пакет, а не тело подкоманды: справочник менеджеров и
// лицензий заполняется не только из CLI. Его же перечитывает администратор
// через «Настройку» после правки licenses.yml, и разъехаться эти два пути не
// имеют права — иначе выпадающий список в карточке пакета зависел бы от того,
// каким способом справочник обновили в последний раз.
package seeds

import (
	"context"
	"fmt"
	"strings"
	"time"

	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Service — заполнение справочников и демо-данных.
type Service struct {
	Repo     *repo.Repo
	Registry *registry.Registry
	// Policies — держатель политик, а не загруженный справочник: bootstrap
	// может идти следом за правкой licenses.yml, и брать надо текущее
	// содержимое файла, а не снимок, сделанный при сборке зависимостей.
	Policies *policy.Holder
	// Now — источник времени, подменяемый в тестах.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Managers переносит справочник менеджеров из плагинов в базу.
//
// Источник правды — плагины: заголовок и формат записи объявлены там, и
// вторая их копия в SQL-миграции разъехалась бы с разбором при первом же
// уточнении формулировки.
func (s *Service) Managers(ctx context.Context) (int, error) {
	plugins := s.Registry.Plugins()
	rows := make([]repo.ManagerSeed, 0, len(plugins))
	for _, p := range plugins {
		rows = append(rows, repo.ManagerSeed{
			Code: p.Code(), Title: p.Title(), EntryFormat: p.EntryFormat(),
		})
	}
	return s.Repo.SeedManagers(ctx, rows)
}

// ErrLicensesNotLoaded — справочник лицензий не прочитался.
//
// Отдельная ошибка, а не «заполнено 0 лицензий»: пустой справочник и
// непрочитанный файл выглядят одинаково по количеству строк, но означают
// противоположное. Молча записать в базу пустоту по нечитаемому файлу значило
// бы стереть уже заполненный справочник.
type ErrLicensesNotLoaded struct {
	Path   string
	Reason string
}

func (e *ErrLicensesNotLoaded) Error() string {
	return fmt.Sprintf("справочник лицензий %s не прочитан: %s", e.Path, e.Reason)
}

// Licenses переносит справочник SPDX из файла политики в таблицу.
//
// Зачем он в базе, если вердикт выносит файл: таблица нужна выпадающему списку
// в карточке пакета и внешнему ключу у заявления лицензии. Расхождение между
// ними не опасно, но список, в котором нет лицензии из файла, мешает
// разработчику её заявить.
func (s *Service) Licenses(ctx context.Context) (int, error) {
	p := s.Policies.Licenses()
	if p == nil {
		return 0, &ErrLicensesNotLoaded{Path: "(не задан)", Reason: "файл не настроен"}
	}
	if p.Failed() {
		return 0, &ErrLicensesNotLoaded{Path: p.Path, Reason: p.Err}
	}
	entries := append(p.SortedAllowed(), p.SortedForbidden()...)
	rows := make([]repo.LicenseSeed, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, repo.LicenseSeed{
			SPDXID: e.SPDXID, Name: e.Name, URL: e.URL,
			Allowed: e.Allowed, Notes: e.Notes,
		})
	}
	return s.Repo.SeedLicenses(ctx, rows)
}

// ImportStats — исход импорта списка пакетов.
type ImportStats struct {
	// Imported — переведены в «одобрен».
	Imported int
	// Skipped — уже были одобрены, трогать нечего.
	Skipped int
	// Invalid — строка не разобралась форматом менеджера.
	Invalid int
	// InvalidLines — сами нераспознанные строки: без них человеку нечего
	// править. Ограничены, чтобы вывод не утонул в битом файле.
	InvalidLines []string
}

// maxInvalidShown — сколько нераспознанных строк показываем.
const maxInvalidShown = 20

// ImportPackageList разово вносит существующий package_list.txt как уже
// одобренные пакеты.
//
// Нужен один раз при заведении сервиса: до него список одобренного жил в
// файлах в GitLab, и без переноса каждый уже используемый пакет пришлось бы
// проводить через модерацию заново. После импорта файлы не читаются — источник
// фиксируется в журнале, чтобы через год было видно, откуда пакет взялся.
//
// Пакеты заводятся одобренными без прогона конвейера — это осознанно: решение
// по ним уже было принято людьми, и прогонять его повторно значило бы
// заблокировать половину работающего кода на время проверки.
func (s *Service) ImportPackageList(
	ctx context.Context, manager string, lines []string, actor *domain.User, origin string,
) (ImportStats, error) {
	var stats ImportStats
	plugin, err := s.Registry.Get(manager)
	if err != nil {
		return stats, err
	}
	now := s.now()
	reason := "Импортирован из " + origin + " как ранее одобренный"

	for _, raw := range lines {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		ref, err := registry.ParseEntry(plugin, line)
		if err != nil {
			stats.Invalid++
			if len(stats.InvalidLines) < maxInvalidShown {
				stats.InvalidLines = append(stats.InvalidLines, line)
			}
			continue
		}
		pkg, err := s.Repo.GetOrCreatePackage(ctx, ref.Manager, ref.Name, ref.DisplayName)
		if err != nil {
			return stats, err
		}
		version, err := s.Repo.CreatePackageVersion(ctx, pkg.ID, ref.Version, ref.RawVersion)
		if err != nil {
			return stats, err
		}
		// Уже одобренную версию не трогаем: повторный запуск импорта по тому
		// же файлу обязан быть безвредным — иначе его боятся запускать, и
		// дописанные в список пакеты так и не попадают в базу.
		if version.Status == "approved" {
			stats.Skipped++
			continue
		}
		if err := s.Repo.MarkVersionImported(ctx, version.ID, reason, now); err != nil {
			return stats, err
		}
		stats.Imported++

		entityID := fmt.Sprintf("%d", version.ID)
		comment := "Импорт из " + origin
		entry := domain.AuditLog{
			Action: "package_imported", EntityType: "package_version", EntityID: &entityID,
			NewValue: map[string]any{
				"manager": ref.Manager, "name": ref.DisplayName,
				"version": ref.RawVersion, "origin": origin,
			},
			Source: "cli", Comment: &comment, CreatedAt: now,
		}
		if actor != nil {
			entry.ActorID = &actor.ID
			entry.ActorName = actor.Username
		} else {
			entry.ActorName = "CLI"
		}
		if err := s.Repo.InsertAuditLog(ctx, entry); err != nil {
			return stats, err
		}
	}
	return stats, nil
}
