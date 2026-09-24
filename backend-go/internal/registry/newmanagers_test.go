package registry_test

import (
	"context"
	"strings"
	"testing"

	"moderation/internal/registry"
)

// pluginWith — плагин менеджера, ходящий в подставной реестр по тем же
// адресам, что задаются конфигурацией.
func pluginWith(t *testing.T, manager string, f *fakeRegistry) registry.Plugin {
	t.Helper()
	r := registry.New(registry.Config{
		MavenURL: "https://maven.test", MavenSearchURL: "https://mavensearch.test",
		ConanURL: "https://conan.test", LuaRocksURL: "https://luarocks.test",
		TerraformURL: "https://terraform.test", PackagistURL: "https://packagist.test",
		HTTP: f,
	})
	p, err := r.Get(manager)
	if err != nil {
		t.Fatalf("Get(%q): %v", manager, err)
	}
	return p
}

func metaFor(t *testing.T, manager, entry string, f *fakeRegistry) registry.Metadata {
	t.Helper()
	plugin := pluginWith(t, manager, f)
	ref, err := registry.ParseEntry(plugin, entry)
	if err != nil {
		t.Fatalf("%s: запись %q не разобрана: %v", manager, entry, err)
	}
	meta, err := plugin.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("%s: FetchMetadata: %v", manager, err)
	}
	return meta
}

// TestMavenMetadata — лицензия из POM, дата из поискового API, sha1 из файла
// рядом с артефактом. Три разных источника, и каждый нужен: реестр maven не
// отдаёт эти сведения одним ответом.
func TestMavenMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://maven.test/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.pom": `
			<project><licenses><license>
				<name>Apache License, Version 2.0</name>
				<url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
			</license></licenses></project>`,
		"https://maven.test/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar.sha1": "abc123def4567890abc123def4567890abc123de  guava.jar",
		`https://mavensearch.test/solrsearch/select?q=g:%22com.google.guava%22+AND+a:%22guava%22+AND+v:%2233.0.0-jre%22&rows=1&wt=json`: `
			{"response":{"docs":[{"timestamp":1705315200000}]}}`,
	}}

	meta := metaFor(t, "maven", "com.google.guava:guava:33.0.0-jre", f)
	if meta.LicenseSPDX != "Apache-2.0" {
		t.Errorf("лицензия = %q, ожидалась Apache-2.0", meta.LicenseSPDX)
	}
	if meta.ChecksumAlgo != "sha1" || len(meta.Checksum) != 40 {
		t.Errorf("контрольная сумма = %s/%q", meta.ChecksumAlgo, meta.Checksum)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Format("2006-01-02") != "2024-01-15" {
		t.Errorf("дата публикации = %v", meta.PublishedAt)
	}
	if meta.ArtifactFilename != "guava-33.0.0-jre.jar" {
		t.Errorf("имя файла = %q", meta.ArtifactFilename)
	}
}

// TestMavenMissingPOMIsNotFound — отсутствие POM означает «такой версии нет»,
// а не «лицензия не указана»: шаг конвейера обязан отличать ошибку
// пользователя от недоступности реестра.
func TestMavenMissingPOMIsNotFound(t *testing.T) {
	plugin := pluginWith(t, "maven", &fakeRegistry{responses: map[string]string{}})
	ref, _ := registry.ParseEntry(plugin, "com.example:lib:1.0.0")
	_, err := plugin.FetchMetadata(context.Background(), ref)
	if err == nil {
		t.Fatal("несуществующая версия принята")
	}
	if !strings.Contains(err.Error(), "отсутствует в реестре") {
		t.Errorf("ошибка не объясняет причину: %v", err)
	}
}

// TestMavenBrokenPOMStillYieldsArtifact — сломанный POM отправляет пакет к
// юристу, а не валит заявку: лицензия не является условием существования
// пакета.
func TestMavenBrokenPOMStillYieldsArtifact(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://maven.test/com/example/lib/1.0.0/lib-1.0.0.pom": "<project><licenses",
	}}
	meta := metaFor(t, "maven", "com.example:lib:1.0.0", f)
	if meta.ArtifactURL == "" {
		t.Error("адрес артефакта потерян из-за сломанного POM")
	}
	if meta.LicenseSPDX != "" {
		t.Errorf("из сломанного POM извлечена лицензия %q", meta.LicenseSPDX)
	}
}

// TestMavenFallsBackToGoogleRepository — AndroidX и другие Android-библиотеки
// не публикуются в Maven Central. 404 первого репозитория должен приводить к
// проверке следующего, а не к ложному «версия отсутствует».
func TestMavenFallsBackToGoogleRepository(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://google-maven.test/androidx/annotation/annotation/1.9.1/annotation-1.9.1.pom": `
			<project><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>`,
	}}
	r := registry.New(registry.Config{
		MavenURL:       "https://central.test, https://google-maven.test",
		MavenSearchURL: "https://mavensearch.test", HTTP: f,
	})
	plugin, err := r.Get("maven")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := registry.ParseEntry(plugin, "androidx.annotation:annotation:1.9.1")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := plugin.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("AndroidX не найден во втором репозитории: %v", err)
	}
	if !strings.HasPrefix(meta.ArtifactURL, "https://google-maven.test/") {
		t.Errorf("артефакт взят не из Google Maven: %s", meta.ArtifactURL)
	}
}

// TestPHPMetadata — Packagist отдаёт дистрибутив, дату и лицензию одним
// ответом; поле shasum содержит sha1, а не sha256, несмотря на имя.
func TestPHPMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://packagist.test/p2/symfony/console.json": `{"packages":{"symfony/console":[
			{"version":"v6.4.2","version_normalized":"6.4.2.0","time":"2023-12-10T08:00:00+00:00",
			 "license":["MIT"],
			 "dist":{"type":"zip","url":"https://api.github.test/repos/symfony/console/zipball/abc",
			         "shasum":"1111111111111111111111111111111111111111"}}]}}`,
	}}

	meta := metaFor(t, "php", "symfony/console:6.4.2", f)
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("лицензия = %q", meta.LicenseSPDX)
	}
	if meta.ChecksumAlgo != "sha1" {
		t.Errorf("алгоритм суммы = %q: Packagist называет поле shasum, а кладёт в него sha1",
			meta.ChecksumAlgo)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Format("2006-01-02") != "2023-12-10" {
		t.Errorf("дата публикации = %v", meta.PublishedAt)
	}
	if !strings.HasSuffix(meta.ArtifactFilename, ".zip") {
		t.Errorf("имя файла = %q", meta.ArtifactFilename)
	}
}

// TestPHPVersionWithLeadingV — v6.4.2 и 6.4.2 это одна версия. Разводить их
// по двум строкам в базе значило бы модерировать один пакет дважды.
func TestPHPVersionWithLeadingV(t *testing.T) {
	plugin := pluginWith(t, "php", &fakeRegistry{responses: map[string]string{}})
	withV, err := registry.ParseEntry(plugin, "symfony/console:v6.4.2")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := registry.ParseEntry(plugin, "symfony/console:6.4.2")
	if err != nil {
		t.Fatal(err)
	}
	if withV.Version != plain.Version {
		t.Errorf("v6.4.2 → %q, а 6.4.2 → %q: один пакет уехал бы в две строки базы",
			withV.Version, plain.Version)
	}
	// Написанное пользователем при этом сохраняется: в карточке он должен
	// видеть свою запись, а не приведённую к канону.
	if withV.RawVersion != "v6.4.2" {
		t.Errorf("исходная запись версии потеряна: %q", withV.RawVersion)
	}
}

// TestConanPicksLatestRevision — под одной версией у рецепта бывает несколько
// ревизий с разными патчами, и берётся последняя по времени, а не первая в
// ответе: порядок элементов сервер не гарантирует.
func TestConanPicksLatestRevision(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://conan.test/v2/conans/zlib/1.3.1/_/_/revisions": `{"revisions":[
			{"revision":"bbbbbbbbbbbbbbbb","time":"2024-03-01T10:00:00Z"},
			{"revision":"aaaaaaaaaaaaaaaa","time":"2024-01-01T10:00:00Z"}]}`,
		"https://conan.test/v2/conans/zlib/1.3.1/_/_/revisions/bbbbbbbbbbbbbbbb/files": `
			{"files":{"conan_export.tgz":{},"conanmanifest.txt":{}}}`,
	}}

	meta := metaFor(t, "conan", "zlib/1.3.1", f)
	if !strings.Contains(meta.ArtifactURL, "bbbbbbbbbbbbbbbb") {
		t.Errorf("взята не последняя ревизия: %s", meta.ArtifactURL)
	}
	if !strings.Contains(meta.ArtifactFilename, "bbbbbbbbbbbb") {
		t.Errorf("ревизия не попала в имя файла: %q — по нему в артефактори "+
			"видно, какое содержимое промодерировано", meta.ArtifactFilename)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Format("2006-01-02") != "2024-03-01" {
		t.Errorf("дата публикации = %v", meta.PublishedAt)
	}
}

// TestConanRejectsUserChannel — запись с user/channel отвергается с
// объяснением, что именно лишнее. Просто «неверный формат» заставило бы
// гадать.
func TestConanRejectsUserChannel(t *testing.T) {
	plugin := pluginWith(t, "conan", &fakeRegistry{responses: map[string]string{}})
	_, err := registry.ParseEntry(plugin, "zlib/1.3.1@user/stable")
	if err == nil {
		t.Fatal("запись с каналом принята")
	}
	if !strings.Contains(err.Error(), "user/channel") {
		t.Errorf("ошибка не объясняет, что лишнее: %v", err)
	}
}

// TestTerraformMetadata — дистрибутив и его sha256 берутся под конкретную
// платформу: у платформ разные байты, и сумма одной ничего не говорит о другой.
func TestTerraformMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://terraform.test/v1/providers/hashicorp/aws/5.31.0/download/linux/amd64": `
			{"os":"linux","arch":"amd64","filename":"terraform-provider-aws_5.31.0_linux_amd64.zip",
			 "download_url":"https://releases.test/aws_5.31.0_linux_amd64.zip",
			 "shasum":"deadbeef"}`,
		"https://terraform.test/v1/providers/hashicorp/aws/5.31.0": `
			{"version":"5.31.0","published_at":"2023-11-20T12:00:00Z"}`,
	}}

	meta := metaFor(t, "terraform", "hashicorp/aws@5.31.0", f)
	if meta.ChecksumAlgo != "sha256" || meta.Checksum != "deadbeef" {
		t.Errorf("контрольная сумма = %s/%q", meta.ChecksumAlgo, meta.Checksum)
	}
	if meta.ArtifactFilename != "terraform-provider-aws_5.31.0_linux_amd64.zip" {
		t.Errorf("имя файла = %q", meta.ArtifactFilename)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Format("2006-01-02") != "2023-11-20" {
		t.Errorf("дата публикации = %v", meta.PublishedAt)
	}
}

// TestTerraformPlatformInEntry — платформу можно указать в записи, и тогда
// скачивается именно её дистрибутив.
func TestTerraformPlatformInEntry(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://terraform.test/v1/providers/hashicorp/aws/5.31.0/download/darwin/arm64": `
			{"download_url":"https://releases.test/aws_darwin_arm64.zip","shasum":"cafe"}`,
	}}
	meta := metaFor(t, "terraform", "hashicorp/aws@5.31.0:darwin_arm64", f)
	if !strings.Contains(meta.ArtifactURL, "darwin_arm64") {
		t.Errorf("скачивается не та платформа: %s", meta.ArtifactURL)
	}
}

// TestLuaRocksMetadata — лицензия достаётся из rockspec разбором одного поля:
// rockspec — это Lua-код, и исполнять его ради строчки лицензии нельзя.
func TestLuaRocksMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://luarocks.test/luasocket-3.1.0-1.rockspec": `
			package = "luasocket"
			version = "3.1.0-1"
			description = {
			   summary = "Network support for Lua",
			   license = "MIT"
			}`,
	}}

	meta := metaFor(t, "luarocks", "luasocket@3.1.0-1", f)
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("лицензия = %q", meta.LicenseSPDX)
	}
	if meta.ArtifactFilename != "luasocket-3.1.0-1.src.rock" {
		t.Errorf("имя файла = %q", meta.ArtifactFilename)
	}
	// Даты публикации luarocks не отдаёт: карантин будет пропущен с пометкой.
	// Выдуманная дата здесь означала бы молча пройденный карантин.
	if meta.PublishedAt != nil {
		t.Errorf("дата публикации = %v, а luarocks её не сообщает", meta.PublishedAt)
	}
}

// TestLuaRocksRequiresRevision — версия без ревизии отвергается: ревизия
// входит в имя файла rock'а, и без неё скачивать нечего.
func TestLuaRocksRequiresRevision(t *testing.T) {
	plugin := pluginWith(t, "luarocks", &fakeRegistry{responses: map[string]string{}})
	_, err := registry.ParseEntry(plugin, "luasocket@3.1.0")
	if err == nil {
		t.Fatal("версия без ревизии принята")
	}
	if !strings.Contains(err.Error(), "РЕВИЗИЕЙ") {
		t.Errorf("ошибка не объясняет, чего не хватает: %v", err)
	}
}
