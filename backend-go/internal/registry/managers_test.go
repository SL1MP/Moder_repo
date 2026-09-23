package registry_test

import (
	"context"
	"strings"
	"testing"

	"moderation/internal/domain"
	"moderation/internal/registry"
)

// newAll — реестр со всеми плагинами и подставным HTTP-клиентом.
func newAll(http registry.Doer) *registry.Registry {
	return registry.New(registry.Config{HTTP: http})
}

// TestEveryManagerCodeHasPlugin — список допустимых менеджеров и набор
// плагинов обязаны совпадать, в обе стороны.
//
// Проверка существует не ради симметрии. Код менеджера попадает в базу через
// CHECK-ограничение, а работает через плагин, и это два разных места. Код без
// плагина означает пакет, который заводится и падает на первом же шаге с
// «менеджер не поддерживается»; плагин без кода — менеджер, которого нет в
// выпадающем списке и который отвергается базой. Оба случая видны только в
// бою.
func TestEveryManagerCodeHasPlugin(t *testing.T) {
	reg := newAll(nil)
	codes := map[string]bool{}
	for _, code := range reg.Codes() {
		codes[code] = true
	}

	for _, code := range domain.ManagerCodes {
		if !codes[code] {
			t.Errorf("менеджер %q объявлен в domain.ManagerCodes, но плагина для него нет: "+
				"пакет заведётся и упадёт на первом шаге", code)
		}
	}
	for code := range codes {
		if !domain.Contains(domain.ManagerCodes, code) {
			t.Errorf("плагин %q есть, но кода нет в domain.ManagerCodes: "+
				"база отвергнет такой пакет CHECK-ограничением", code)
		}
	}

	// Порядок тоже совпадает: по нему строится выпадающий список менеджеров
	// в интерфейсе, и расхождение означало бы два разных порядка в одном UI.
	got := strings.Join(reg.Codes(), ",")
	want := strings.Join(domain.ManagerCodes, ",")
	if got != want {
		t.Errorf("порядок плагинов = %s, в domain.ManagerCodes = %s", got, want)
	}
}

// TestPluginContractIsComplete — каждый плагин отвечает на весь контракт.
//
// Пустой формат записи или пустой заголовок — это не косметика: формат
// показывается пользователю в подсказке поля ввода и в каждом сообщении об
// ошибке разбора, а заголовок — в выпадающем списке. Пустая строка там
// означает менеджер без имени.
func TestPluginContractIsComplete(t *testing.T) {
	for _, plugin := range newAll(nil).Plugins() {
		code := plugin.Code()
		if strings.TrimSpace(plugin.Title()) == "" {
			t.Errorf("%s: пустой Title — в списке менеджеров будет пустая строка", code)
		}
		if strings.TrimSpace(plugin.EntryFormat()) == "" {
			t.Errorf("%s: пустой EntryFormat — подсказка и сообщения об ошибках будут пустыми", code)
		}
		if strings.TrimSpace(plugin.DisplayName(" X ")) != "X" {
			t.Errorf("%s: DisplayName не обрезает пробелы", code)
		}
	}
}

// TestEntryRoundTrip — запись в формате менеджера разбирается и приводится к
// той же ссылке. Проверяется на примере из его же подсказки: если пример из
// EntryFormat не разбирается, пользователь получает ошибку, сделав ровно то,
// что попросили.
func TestEntryRoundTrip(t *testing.T) {
	cases := map[string]struct{ entry, name, version string }{
		"pypi":      {"requests==2.31.0", "requests", "2.31.0"},
		"npm":       {"lodash@4.17.21", "lodash", "4.17.21"},
		"nuget":     {"Newtonsoft.Json@13.0.3", "newtonsoft.json", "13.0.3"},
		"maven":     {"com.google.guava:guava:33.0.0-jre", "com.google.guava:guava", "33.0.0-jre"},
		"docker":    {"alpine:3.19", "library/alpine", "3.19"},
		"conan":     {"zlib/1.3.1", "zlib", "1.3.1"},
		"luarocks":  {"luasocket@3.1.0-1", "luasocket", "3.1.0-1"},
		"terraform": {"hashicorp/aws@5.31.0", "hashicorp/aws", "5.31.0"},
		"php":       {"symfony/console:6.4.2", "symfony/console", "6.4.2"},
		"git": {
			"https://github.com/org/repo@v1.2.3",
			"https://github.com/org/repo", "v1.2.3",
		},
		"files": {
			"https://example.com/tool.tar.gz@sha256:" + strings.Repeat("a", 64),
			"https://example.com/tool.tar.gz", "sha256:" + strings.Repeat("a", 64),
		},
	}

	reg := newAll(nil)
	for code, want := range cases {
		plugin, err := reg.Get(code)
		if err != nil {
			t.Errorf("%s: плагин не найден: %v", code, err)
			continue
		}
		ref, err := registry.ParseEntry(plugin, want.entry)
		if err != nil {
			t.Errorf("%s: запись %q не разобрана: %v", code, want.entry, err)
			continue
		}
		if ref.Name != want.name {
			t.Errorf("%s: имя = %q, ожидалось %q", code, ref.Name, want.name)
		}
		if ref.Version != want.version {
			t.Errorf("%s: версия = %q, ожидалась %q", code, ref.Version, want.version)
		}
		if ref.Manager != code {
			t.Errorf("%s: менеджер в ссылке = %q", code, ref.Manager)
		}
	}
}

// TestMovingVersionsAreRefused — версии, которые меняются под тем же именем,
// не принимаются.
//
// Это не придирка к формату. Смысл модерации в том, что решение относится к
// конкретным байтам. «latest», «-SNAPSHOT» и «dev-» байты не фиксируют:
// завтра по тому же имени будет другое содержимое, а решение останется
// прежним — то есть будет разрешать то, чего никто не проверял.
func TestMovingVersionsAreRefused(t *testing.T) {
	cases := map[string]struct{ name, version string }{
		"docker": {"alpine", "latest"},
		"maven":  {"com.example:lib", "1.0-SNAPSHOT"},
		"php":    {"symfony/console", "dev-main"},
	}
	reg := newAll(nil)
	for code, c := range cases {
		plugin, err := reg.Get(code)
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		if _, err := registry.MakeRef(plugin, c.name, c.version); err == nil {
			t.Errorf("%s: версия %q принята, а она меняется под тем же именем",
				code, c.version)
		}
	}
}

// TestDetectByFileCoversNewManagers — по перетащенному файлу зависимостей
// интерфейс подсказывает менеджер. Без этого пользователь выбирает его
// вручную и ошибается.
func TestDetectByFileCoversNewManagers(t *testing.T) {
	reg := newAll(nil)
	want := map[string]string{
		"pom.xml":             "maven",
		"build.gradle":        "maven",
		"composer.json":       "php",
		"composer.lock":       "php",
		"conanfile.txt":       "conan",
		"conanfile.py":        "conan",
		"Dockerfile":          "docker",
		"lib.rockspec":        "luarocks",
		".terraform.lock.hcl": "terraform",
		// Путь до файла к делу не относится: пользователь перетаскивает файл,
		// и как он называется у него на машине — его дело.
		"/home/dev/project/pom.xml": "maven",
	}
	for file, manager := range want {
		if got := reg.DetectByFile(file); got != manager {
			t.Errorf("по файлу %q определён менеджер %q, ожидался %q", file, got, manager)
		}
	}
}

// TestFilesRequiresDigest — у принесённого файла хеш обязателен и указывается
// заранее. Посчитать его по скачанному значило бы промодерировать что угодно,
// что лежало по ссылке в момент скачивания.
func TestFilesRequiresDigest(t *testing.T) {
	plugin, err := newAll(nil).Get("files")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ParseEntry(plugin, "https://example.com/tool.tar.gz"); err == nil {
		t.Error("ссылка без хеша принята — модерировать было бы нечего")
	}
	if _, err := registry.MakeRef(plugin, "https://example.com/t.zip", "sha256:короткий"); err == nil {
		t.Error("принят хеш неверной длины")
	}
	// file:// читал бы диск воркера, а не принесённый файл.
	if _, err := registry.MakeRef(plugin, "file:///etc/passwd",
		"sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Error("принята ссылка file:// — промодерирован был бы файл с диска сервиса")
	}
}

// TestFilesMetadataCarriesDeclaredChecksum — заявленный хеш попадает в
// метаданные, и шаг скачивания сверит его ДО записи в промежуточную зону.
func TestFilesMetadataCarriesDeclaredChecksum(t *testing.T) {
	plugin, err := newAll(nil).Get("files")
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	ref, err := registry.ParseEntry(plugin,
		"https://example.com/dir/tool.tar.gz@sha256:"+digest)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := plugin.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.ChecksumAlgo != "sha256" || meta.Checksum != digest {
		t.Errorf("контрольная сумма = %s/%s", meta.ChecksumAlgo, meta.Checksum)
	}
	if meta.ArtifactURL != "https://example.com/dir/tool.tar.gz" {
		t.Errorf("адрес артефакта = %q", meta.ArtifactURL)
	}
	if meta.ArtifactFilename != "tool.tar.gz" {
		t.Errorf("имя файла = %q", meta.ArtifactFilename)
	}
}

// TestDownloaderManagers — docker и git забирают артефакт сами, остальные
// идут обычным GET. Проверка удерживает это различие: плагин, случайно
// потерявший Downloader, молча начнёт скачиваться по пустому ArtifactURL.
func TestDownloaderManagers(t *testing.T) {
	want := map[string]bool{"docker": true, "git": true}
	for _, plugin := range newAll(nil).Plugins() {
		_, ok := plugin.(registry.Downloader)
		if ok != want[plugin.Code()] {
			t.Errorf("%s: Downloader=%v, ожидалось %v", plugin.Code(), ok, want[plugin.Code()])
		}
	}
}

// TestOSVEcosystemIsEmptyWhereBaseHasNone — экосистема OSV либо настоящая,
// либо пустая.
//
// Выдуманное имя («LuaRocks», которого в базе нет) выглядело бы как успешная
// проверка по базе, которая ничего не нашла, — то есть как «уязвимостей нет».
// Пустая строка говорит шагу правду: эту экосистему база не покрывает.
func TestOSVEcosystemIsEmptyWhereBaseHasNone(t *testing.T) {
	covered := map[string]string{
		"pypi": "PyPI", "npm": "npm", "go": "Go", "nuget": "NuGet",
		"maven": "Maven", "php": "Packagist",
	}
	for _, plugin := range newAll(nil).Plugins() {
		got := plugin.OSVEcosystem()
		if want, ok := covered[plugin.Code()]; ok {
			if got != want {
				t.Errorf("%s: экосистема OSV = %q, ожидалась %q", plugin.Code(), got, want)
			}
			continue
		}
		if got != "" {
			t.Errorf("%s: экосистема OSV = %q, но в базе OSV её нет — "+
				"проверка выглядела бы выполненной", plugin.Code(), got)
		}
	}
}
