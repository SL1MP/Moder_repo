package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"moderation/internal/config"
)

// Сборка зависимостей маршрутов. Проверка существует из-за реальной ошибки:
// маршруты чтения уехали в релиз объявленными в роутере, но не подключёнными
// здесь — сервис поднимался, а /api/v1/managers отвечал 404. Компилятор такое
// не ловит: незаполненное поле структуры остаётся nil и это законно.
func TestBuildOptionsMountsEverything(t *testing.T) {
	policyDir := t.TempDir()
	blacklistFile := filepath.Join(policyDir, "blacklist.yml")
	licensesFile := filepath.Join(policyDir, "licenses.yml")
	if err := os.WriteFile(blacklistFile, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("не создан тестовый blacklist: %v", err)
	}
	if err := os.WriteFile(licensesFile, []byte(`allowed:
  - spdx_id: MIT
    name: MIT License
forbidden: []
`), 0o600); err != nil {
		t.Fatalf("не создан тестовый справочник лицензий: %v", err)
	}
	cfg := testConfig(t, map[string]string{
		"BLACKLIST_FILE":        blacklistFile,
		"ALLOWED_LICENSES_FILE": licensesFile,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// pool = nil: сборка зависимостей к базе не ходит, а поднимать Postgres
	// ради проверки того, что поля заполнены, незачем.
	options, blacklist, _ := buildOptions(cfg, nil, logger)

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
	// Тестовые политики создаются рядом с тестом, а не читаются из ../config:
	// Docker-образ для go test собирается с context=backend-go и намеренно не
	// содержит соседний каталог репозитория. Проверяем именно сборку зависимостей,
	// не расположение файлов на машине, где запущен тест.
	if blacklist.Failed() {
		t.Errorf("blacklist не прочитан: %s", blacklist.Err)
	}
	if licenses := options.Licenses.Policies.Licenses(); licenses.Failed() {
		t.Errorf("справочник лицензий не прочитан: %s", licenses.Err)
	}
}

// Хранилище отчётов недоступно — сервис всё равно собирается, просто без
// выдачи отчётов. Падать на старте из-за артефактори нельзя: health обязан
// отвечать, а чтение — работать.
//
// Адрес здесь заведомо мёртвый, и это важно: у ARTIFACT_BASE_URL есть значение
// по умолчанию, поэтому «не настроено» проверяется обращением к артефактори, а
// не пустой строкой в конфигурации.
func TestBuildOptionsWithoutStorage(t *testing.T) {
	cfg := testConfig(t, map[string]string{
		// 127.0.0.1:1 — порт, на котором заведомо никто не слушает: соединение
		// отвергается сразу, без ожидания таймаута.
		"ARTIFACT_BASE_URL": "http://127.0.0.1:1",
	})
	options, _, st := buildOptions(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if options.Reports != nil {
		t.Error("при недоступном артефактори выдача отчётов подключаться не должна")
	}
	if st != nil {
		t.Error("хранилища не собраны — наблюдатель сканирования запускать не на чем")
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
	options, blacklist, _ := buildOptions(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !blacklist.Failed() {
		t.Error("отсутствующий файл blacklist должен быть отмечен как неудача, а не как пустой список")
	}
	if !options.Licenses.Policies.Licenses().Failed() {
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
