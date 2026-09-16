package main

import (
	"io"
	"log/slog"
	"testing"

	"moderation/internal/config"
)

// Сборка зависимостей маршрутов. Проверка существует из-за реальной ошибки:
// маршруты чтения уехали в релиз объявленными в роутере, но не подключёнными
// здесь — сервис поднимался, а /api/v1/managers отвечал 404. Компилятор такое
// не ловит: незаполненное поле структуры остаётся nil и это законно.
func TestBuildOptionsMountsEverything(t *testing.T) {
	cfg := testConfig(t, map[string]string{
		"BLACKLIST_FILE":        "../../../config/blacklist.yml",
		"ALLOWED_LICENSES_FILE": "../../../config/licenses.yml",
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// pool = nil: сборка зависимостей к базе не ходит, а поднимать Postgres
	// ради проверки того, что поля заполнены, незачем.
	options, blacklist := buildOptions(cfg, nil, logger)

	if options.Auth == nil {
		t.Error("не подключена проверка токенов")
	}
	if options.Packages == nil {
		t.Error("не подключены маршруты базы пакетов")
	}
	if options.Requests == nil {
		t.Error("не подключены маршруты заявок")
	}
	if options.Licenses == nil {
		t.Error("не подключён справочник лицензий")
	}
	if options.Queues == nil {
		t.Error("не подключены очереди ролей")
	}
	if options.Comments == nil {
		t.Error("не подключены обсуждения")
	}
	if options.Notifications == nil {
		t.Error("не подключены уведомления")
	}
	if blacklist == nil {
		t.Fatal("правила blacklist не загружены вовсе")
	}
	// Файлы политик лежат в репозитории и обязаны читаться: если этот тест
	// краснеет, значит сломан их формат, а не путь в тесте.
	if blacklist.Failed() {
		t.Errorf("blacklist не прочитан: %s", blacklist.Err)
	}
	if options.Licenses.Policy.Failed() {
		t.Errorf("справочник лицензий не прочитан: %s", options.Licenses.Policy.Err)
	}
}

// Хранилище отчётов не настроено — сервис всё равно собирается, просто без
// выдачи отчётов. Падать на старте из-за MinIO нельзя.
func TestBuildOptionsWithoutStorage(t *testing.T) {
	cfg := testConfig(t, nil)
	options, _ := buildOptions(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if options.Reports != nil {
		t.Error("без S3_ENDPOINT выдача отчётов подключаться не должна")
	}
	if options.Auth == nil || options.Packages == nil {
		t.Error("остальные маршруты обязаны подключиться и без хранилища")
	}
}

// Непрочитанный файл политики не роняет сборку, но и не выдаёт себя за
// пустой список: Failed() должен быть виден вызывающему.
func TestBuildOptionsSurvivesBrokenPolicyFiles(t *testing.T) {
	cfg := testConfig(t, map[string]string{
		"BLACKLIST_FILE":        "/nonexistent/blacklist.yml",
		"ALLOWED_LICENSES_FILE": "/nonexistent/licenses.yml",
	})
	options, blacklist := buildOptions(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !blacklist.Failed() {
		t.Error("отсутствующий файл blacklist должен быть отмечен как неудача, а не как пустой список")
	}
	if !options.Licenses.Policy.Failed() {
		t.Error("отсутствующий справочник лицензий должен быть отмечен как неудача")
	}
}

func testConfig(t *testing.T, extra map[string]string) *config.Config {
	t.Helper()
	env := map[string]string{"DATABASE_URL": "postgres://localhost/moderation"}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("конфигурация теста невалидна: %v", err)
	}
	return cfg
}
