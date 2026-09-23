package seeds

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Интеграционные тесты заполнения справочников и импорта списков.
//
// Реальный Postgres, не мок: половина проверяемого здесь — это поведение SQL
// (ON CONFLICT, COALESCE, повторный запуск), и мок репозитория проверял бы
// собственную реализацию мока. Без DSN тест пропускается с названной причиной.
func mustService(t *testing.T, licensesFile string) (*Service, *repo.Repo, func()) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	pool, err := db.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	r := repo.New(pool)
	return &Service{
		Repo:     r,
		Registry: registry.New(registry.Config{}),
		Policies: policy.NewHolder("", licensesFile),
	}, r, func() { pool.Close() }
}

// licensesFile кладёт справочник лицензий во временный файл.
func licensesFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "licenses.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("справочник лицензий не записан: %v", err)
	}
	return path
}

// TestSeedManagersCoversEveryPlugin: справочник менеджеров в базе обязан
// совпадать со списком плагинов. Расхождение видно только здесь: интерфейс
// читает таблицу, а разбор строки делает плагин, и менеджер, забытый в
// таблице, выглядит как «такого менеджера нет» при работающем разборе.
func TestSeedManagersCoversEveryPlugin(t *testing.T) {
	s, r, cleanup := mustService(t, "")
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Managers(ctx); err != nil {
		t.Fatalf("справочник менеджеров: %v", err)
	}
	rows, err := r.ListManagers(ctx)
	if err != nil {
		t.Fatalf("чтение справочника: %v", err)
	}
	inDB := map[string]string{}
	for _, m := range rows {
		inDB[m.Code] = m.EntryFormat
	}
	for _, plugin := range s.Registry.Plugins() {
		format, ok := inDB[plugin.Code()]
		if !ok {
			t.Errorf("менеджер %s есть плагином, но его нет в справочнике базы", plugin.Code())
			continue
		}
		// Формат записи — подсказка, которую видит разработчик в карточке.
		// Разъехавшись с разбором, она превращается в инструкцию, по которой
		// заявку завести нельзя.
		if format != plugin.EntryFormat() {
			t.Errorf("менеджер %s: в базе формат %q, плагин ожидает %q",
				plugin.Code(), format, plugin.EntryFormat())
		}
	}
}

// TestSeedManagersIsIdempotent: повторный bootstrap ничего не заводит заново.
func TestSeedManagersIsIdempotent(t *testing.T) {
	s, _, cleanup := mustService(t, "")
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Managers(ctx); err != nil {
		t.Fatalf("первый проход: %v", err)
	}
	created, err := s.Managers(ctx)
	if err != nil {
		t.Fatalf("второй проход: %v", err)
	}
	if created != 0 {
		t.Fatalf("повторный проход завёл %d менеджеров, ожидалось 0", created)
	}
}

// TestSeedLicensesWritesBothLists: в таблицу попадают и разрешённые, и
// запрещённые лицензии, с правильным признаком.
//
// Запрещённые нужны в списке ровно затем, чтобы разработчик мог заявить
// лицензию, которую сервис потом отклонит с внятной причиной. Справочник из
// одних разрешённых заставил бы его гадать, почему его лицензии в списке нет.
func TestSeedLicensesWritesBothLists(t *testing.T) {
	allowed := "SEED-ALLOWED-" + unique()
	forbidden := "SEED-FORBIDDEN-" + unique()
	path := licensesFile(t, fmt.Sprintf(`allowed:
  - spdx_id: %s
    name: Разрешённая
    url: https://example.invalid/allowed
forbidden:
  - spdx_id: %s
    name: Запрещённая
    notes: только с разрешения юристов
`, allowed, forbidden))

	s, r, cleanup := mustService(t, path)
	defer cleanup()
	ctx := context.Background()

	created, err := s.Licenses(ctx)
	if err != nil {
		t.Fatalf("справочник лицензий: %v", err)
	}
	if created != 2 {
		t.Fatalf("заведено %d лицензий, ожидалось 2", created)
	}

	byID := map[string]bool{}
	rows, err := r.ListLicenses(ctx)
	if err != nil {
		t.Fatalf("чтение лицензий: %v", err)
	}
	for _, l := range rows {
		byID[l.SPDXID] = l.Allowed
	}
	if got, ok := byID[allowed]; !ok || !got {
		t.Errorf("разрешённая лицензия %s: в базе allowed=%v (есть: %v)", allowed, got, ok)
	}
	if got, ok := byID[forbidden]; !ok || got {
		t.Errorf("запрещённая лицензия %s: в базе allowed=%v (есть: %v)", forbidden, got, ok)
	}
}

// TestSeedLicensesRefusesUnreadableFile: нечитаемый файл — ошибка, а не
// «ноль лицензий».
//
// Разница принципиальная: заполнить справочник пустотой по непрочитанному
// файлу значит стереть автодополнение в карточке пакета и не сказать об этом
// ни слова. Ровно так теряется знание о том, что справочник вообще был.
func TestSeedLicensesRefusesUnreadableFile(t *testing.T) {
	s, _, cleanup := mustService(t, filepath.Join(t.TempDir(), "нет-такого-файла.yml"))
	defer cleanup()

	created, err := s.Licenses(context.Background())
	if err == nil {
		t.Fatalf("нечитаемый справочник принят молча, заведено %d", created)
	}
	var notLoaded *ErrLicensesNotLoaded
	if !asErr(err, &notLoaded) {
		t.Fatalf("ожидалась ErrLicensesNotLoaded, получено %T: %v", err, err)
	}
	if created != 0 {
		t.Fatalf("при нечитаемом справочнике заведено %d лицензий", created)
	}
}

// TestImportMarksApprovedAndLogs: импорт переводит пакет в «одобрен», ставит
// дату одобрения и оставляет запись в журнале с источником.
//
// Дата одобрения проверяется отдельно: без неё перепроверка по новой базе
// уязвимостей, которая отбирает пакеты по approved_at, импортированные пакеты
// никогда не возьмёт — и они останутся неперепроверенными навсегда.
func TestImportMarksApprovedAndLogs(t *testing.T) {
	s, r, cleanup := mustService(t, "")
	defer cleanup()
	ctx := context.Background()

	name := "imp-" + unique()
	origin := "gitlab:тест/репо:package_list.txt"
	stats, err := s.ImportPackageList(ctx, "pypi",
		[]string{"# комментарий", "", name + "==1.2.3   # хвост"}, nil, origin)
	if err != nil {
		t.Fatalf("импорт: %v", err)
	}
	if stats.Imported != 1 || stats.Skipped != 0 || stats.Invalid != 0 {
		t.Fatalf("итог импорта %+v, ожидалось 1/0/0", stats)
	}

	version := findVersion(t, r, name, "1.2.3")
	if version.Status != "approved" {
		t.Errorf("статус версии %q, ожидался approved", version.Status)
	}
	if version.ApprovedAt == nil {
		t.Error("у импортированной версии нет даты одобрения")
	}
	if version.LicenseSource == nil || *version.LicenseSource != "manual" {
		t.Errorf("источник лицензии %v, ожидался manual", version.LicenseSource)
	}
	if version.StatusReason == nil || !strings.Contains(*version.StatusReason, origin) {
		t.Errorf("в причине статуса нет источника: %v", version.StatusReason)
	}

	entityID := fmt.Sprintf("%d", version.ID)
	entries, err := r.ListAuditLog(ctx, repo.AuditFilter{EntityID: entityID, Limit: 10})
	if err != nil {
		t.Fatalf("чтение журнала: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("в журнале %d записей об импорте, ожидалась 1", len(entries))
	}
	if entries[0].Action != "package_imported" || entries[0].Source != "cli" {
		t.Errorf("запись журнала: действие %q, источник %q", entries[0].Action, entries[0].Source)
	}
}

// TestImportIsIdempotent: повторный прогон по тому же файлу ничего не меняет.
//
// Это не украшение: импорт запускают повторно, когда в список дописали пакет.
// Команда, которая на повторе переставляет дату одобрения уже одобренному,
// выглядит опасной — и её перестают запускать вовсе, а дописанные пакеты так
// и не попадают в базу.
func TestImportIsIdempotent(t *testing.T) {
	s, r, cleanup := mustService(t, "")
	defer cleanup()
	ctx := context.Background()

	name := "imp-idem-" + unique()
	lines := []string{name + "==4.5.6"}
	if _, err := s.ImportPackageList(ctx, "pypi", lines, nil, "первый"); err != nil {
		t.Fatalf("первый импорт: %v", err)
	}
	first := findVersion(t, r, name, "4.5.6")

	// Часы сдвигаем, чтобы повторная запись даты была заметна.
	s.Now = func() time.Time { return time.Now().UTC().Add(48 * time.Hour) }
	stats, err := s.ImportPackageList(ctx, "pypi", lines, nil, "второй")
	if err != nil {
		t.Fatalf("второй импорт: %v", err)
	}
	if stats.Imported != 0 || stats.Skipped != 1 {
		t.Fatalf("повторный импорт: %+v, ожидалось 0 внесённых и 1 пропущенный", stats)
	}

	second := findVersion(t, r, name, "4.5.6")
	if !second.ApprovedAt.Equal(*first.ApprovedAt) {
		t.Errorf("дата одобрения переставлена: было %v, стало %v", first.ApprovedAt, second.ApprovedAt)
	}
	if second.StatusReason == nil || !strings.Contains(*second.StatusReason, "первый") {
		t.Errorf("причина статуса перезаписана вторым прогоном: %v", second.StatusReason)
	}
}

// TestImportCountsInvalidLines: нераспознанная строка не роняет импорт, но и не
// теряется — её возвращают человеку, чтобы было что править.
func TestImportCountsInvalidLines(t *testing.T) {
	s, _, cleanup := mustService(t, "")
	defer cleanup()

	name := "imp-mixed-" + unique()
	stats, err := s.ImportPackageList(context.Background(), "pypi",
		[]string{name + "==1.0.0", "это не пакет", "и это тоже"}, nil, "тест")
	if err != nil {
		t.Fatalf("импорт: %v", err)
	}
	if stats.Imported != 1 {
		t.Errorf("внесено %d, ожидался 1", stats.Imported)
	}
	if stats.Invalid != 2 {
		t.Errorf("не распознано %d, ожидалось 2", stats.Invalid)
	}
	if len(stats.InvalidLines) != 2 {
		t.Errorf("вернулось %d нераспознанных строк, ожидалось 2: %v",
			len(stats.InvalidLines), stats.InvalidLines)
	}
}

// TestImportRejectsUnknownManager: неизвестный менеджер — ошибка до записи.
func TestImportRejectsUnknownManager(t *testing.T) {
	s, _, cleanup := mustService(t, "")
	defer cleanup()

	if _, err := s.ImportPackageList(context.Background(), "нетакого",
		[]string{"pkg==1.0.0"}, nil, "тест"); err == nil {
		t.Fatal("импорт с неизвестным менеджером прошёл без ошибки")
	}
}

// findVersion читает версию пакета по имени и версии.
func findVersion(t *testing.T, r *repo.Repo, name, version string) *domain.PackageVersion {
	t.Helper()
	ctx := context.Background()
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("чтение пакета %s: %v", name, err)
	}
	v, err := r.CreatePackageVersion(ctx, pkg.ID, version, version)
	if err != nil {
		t.Fatalf("чтение версии %s@%s: %v", name, version, err)
	}
	return v
}

func unique() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func asErr(err error, target **ErrLicensesNotLoaded) bool {
	for err != nil {
		if e, ok := err.(*ErrLicensesNotLoaded); ok {
			*target = e
			return true
		}
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapped.Unwrap()
	}
	return false
}
