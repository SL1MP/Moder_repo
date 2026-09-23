package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"moderation/internal/policy"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const goodBlacklist = `rules:
  - manager: pypi
    name: badpkg
    reason: "известная закладка"
`

const goodLicenses = `licenses:
  - spdx_id: MIT
    name: MIT License
    allowed: true
  - spdx_id: AGPL-3.0
    name: GNU AGPL v3
    allowed: false
`

// TestReloadPicksUpChanges — правка файла подхватывается без перезапуска.
//
// Ради этого перезагрузка и заводилась: blacklist правят в тот момент, когда
// надо срочно запретить пакет, а перезапуск api-go рвёт открытые запросы.
func TestReloadPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	blPath := filepath.Join(dir, "blacklist.yml")
	licPath := filepath.Join(dir, "licenses.yml")
	writeFile(t, blPath, goodBlacklist)
	writeFile(t, licPath, goodLicenses)

	h := policy.NewHolder(blPath, licPath)
	if h.Blacklist().Find("pypi", "badpkg", "1.0.0") == nil {
		t.Fatal("правило из файла не загружено")
	}
	if h.Blacklist().Find("pypi", "worsepkg", "1.0.0") != nil {
		t.Fatal("найдено правило, которого в файле нет")
	}

	writeFile(t, blPath, goodBlacklist+`  - manager: pypi
    name: worsepkg
    reason: "добавлено на ходу"
`)
	result := h.Reload()
	if !result.OK() {
		t.Fatalf("перезагрузка не удалась: %+v", result)
	}
	if h.Blacklist().Find("pypi", "worsepkg", "1.0.0") == nil {
		t.Error("новое правило не подхвачено — перезагрузка не работает")
	}
	if result.BlacklistRules != 2 {
		t.Errorf("правил в ответе: %d, ожидалось 2", result.BlacklistRules)
	}
}

// TestReloadKeepsOldRulesOnBrokenFile — сломанный файл НЕ подменяет прежние
// правила.
//
// Иначе опечатка в blacklist.yml мгновенно снимала бы все запреты — ровно в
// тот момент, когда его правят второпях. Прежние правила продолжают
// действовать, а ошибка возвращается вызывающему.
func TestReloadKeepsOldRulesOnBrokenFile(t *testing.T) {
	dir := t.TempDir()
	blPath := filepath.Join(dir, "blacklist.yml")
	licPath := filepath.Join(dir, "licenses.yml")
	writeFile(t, blPath, goodBlacklist)
	writeFile(t, licPath, goodLicenses)

	h := policy.NewHolder(blPath, licPath)

	writeFile(t, blPath, "rules: [ не yaml : : :")
	result := h.Reload()
	if result.OK() {
		t.Fatal("сломанный файл принят как успешная перезагрузка")
	}
	if result.BlacklistError == "" {
		t.Error("ошибка не названа — администратору нечего чинить")
	}
	// Ключевое: запрет остался в силе.
	if h.Blacklist().Find("pypi", "badpkg", "1.0.0") == nil {
		t.Error("сломанный файл снял действующие запреты — опечатка открыла бы контур")
	}
	if h.Blacklist().Failed() {
		t.Error("действующие правила помечены сломанными, хотя они прежние и исправные")
	}
	// Справочник лицензий при этом не пострадал: файлы независимы.
	if result.LicensesError != "" {
		t.Errorf("исправный справочник лицензий объявлен сломанным: %s", result.LicensesError)
	}
}

// TestHolderReportsBrokenFileFromTheStart — файла не было с самого начала.
//
// Подменять нечем, и держать nil нельзя: шаг blacklist на nil не отличит
// «запрещать нечего» от «мы не знаем, что запрещено». Кладём непрочитанную
// политику — она сама себя объявляет сломанной, и пакет уходит DevSecOps.
func TestHolderReportsBrokenFileFromTheStart(t *testing.T) {
	h := policy.NewHolder("/nonexistent/blacklist.yml", "/nonexistent/licenses.yml")
	if h.Blacklist() == nil || h.Licenses() == nil {
		t.Fatal("держатель отдал nil вместо политики — шаг конвейера получит nil pointer")
	}
	if !h.Blacklist().Failed() {
		t.Error("отсутствующий файл выдан за пустой список правил")
	}
	if !h.Licenses().Failed() {
		t.Error("отсутствующий справочник выдан за пустой")
	}
	// Непрочитанный справочник запрещает всё: каждый пакет уходит юристу.
	// Шумно, но безопасно — обратное пропустило бы AGPL молча.
	if h.Licenses().IsAllowed("MIT") {
		t.Error("непрочитанный справочник разрешил лицензию")
	}
}

// TestReloadedAtMovesEvenOnFailure — время обновляется и при неудаче.
//
// Вопрос «когда последний раз ПЫТАЛИСЬ перечитать» не менее важен, чем «когда
// получилось»: без него неудачная перезагрузка выглядит как не случившаяся.
func TestReloadedAtMovesEvenOnFailure(t *testing.T) {
	dir := t.TempDir()
	blPath := filepath.Join(dir, "blacklist.yml")
	writeFile(t, blPath, goodBlacklist)

	h := policy.NewHolder(blPath, filepath.Join(dir, "нет.yml"))
	first := h.ReloadedAt()
	if first.IsZero() {
		t.Fatal("время первой загрузки не проставлено")
	}
	if result := h.Reload(); result.OK() {
		t.Fatal("отсутствующий справочник принят")
	}
	if !h.ReloadedAt().After(first) && h.ReloadedAt() != first {
		t.Error("время попытки не обновилось")
	}
}
