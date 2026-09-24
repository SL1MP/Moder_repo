package registry_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"moderation/internal/registry"
)

// fakeRegistry — фейковый реестр: адрес -> тело ответа. Отсутствующий адрес
// даёт 404, что позволяет проверять и путь «версии нет».
type fakeRegistry struct {
	responses   map[string]string
	requested   []string
	statuses    map[string]int
	headers     map[string]http.Header
	seenHeaders []http.Header
}

func (f *fakeRegistry) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	f.requested = append(f.requested, url)
	f.seenHeaders = append(f.seenHeaders, req.Header.Clone())
	body, ok := f.responses[url]
	status := http.StatusOK
	if !ok {
		status, body = http.StatusNotFound, `{"message":"not found"}`
	}
	if configured, exists := f.statuses[url]; exists {
		status = configured
	}
	header := http.Header{}
	if configured, exists := f.headers[url]; exists {
		header = configured.Clone()
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}, nil
}

func pluginFor(t *testing.T, manager string, f *fakeRegistry) registry.Plugin {
	t.Helper()
	r := registry.New(registry.Config{
		PyPIURL: "https://pypi.test", NpmURL: "https://npm.test",
		GoProxy: "https://goproxy.test", NuGetURL: "https://nuget.test",
		HTTP: f,
	})
	p, err := r.Get(manager)
	if err != nil {
		t.Fatalf("Get(%q): %v", manager, err)
	}
	return p
}

// --------------------------------------------------------------------- разбор записи

func TestParseEntryPerManager(t *testing.T) {
	cases := []struct {
		manager, entry  string
		name, display   string
		version, rawVer string
	}{
		{"pypi", "Requests==2.31.0", "requests", "Requests", "2.31.0", "2.31.0"},
		{"pypi", "zope.interface==5.4.0", "zope-interface", "zope.interface", "5.4.0", "5.4.0"},
		{"npm", "lodash@4.17.21", "lodash", "lodash", "4.17.21", "4.17.21"},
		// Scoped-пакет: «@» и начало scope, и разделитель версии.
		{"npm", "@babel/core@7.24.0", "@babel/core", "@babel/core", "7.24.0", "7.24.0"},
		{"go", "github.com/gin-gonic/gin@v1.9.1", "github.com/gin-gonic/gin",
			"github.com/gin-gonic/gin", "v1.9.1", "v1.9.1"},
		// Регистр в пути модуля сохраняется в DisplayName — именно он уходит в proxy.
		{"go", "github.com/Sirupsen/logrus@v1.0.0", "github.com/sirupsen/logrus",
			"github.com/Sirupsen/logrus", "v1.0.0", "v1.0.0"},
		{"nuget", "Newtonsoft.Json@13.0.3", "newtonsoft.json", "Newtonsoft.Json", "13.0.3", "13.0.3"},
	}
	f := &fakeRegistry{responses: map[string]string{}}
	for _, c := range cases {
		ref, err := registry.ParseEntry(pluginFor(t, c.manager, f), c.entry)
		if err != nil {
			t.Errorf("%s: ParseEntry(%q): %v", c.manager, c.entry, err)
			continue
		}
		if ref.Name != c.name || ref.DisplayName != c.display ||
			ref.Version != c.version || ref.RawVersion != c.rawVer {
			t.Errorf("%s: ParseEntry(%q) = %+v, ожидалось name=%q display=%q version=%q",
				c.manager, c.entry, ref, c.name, c.display, c.version)
		}
	}
}

// TestGoVersionGetsVPrefix — «1.9.1» без v допускается на входе и
// нормализуется: go module proxy без префикса не отвечает.
func TestGoVersionGetsVPrefix(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	ref, err := registry.ParseEntry(pluginFor(t, "go", f), "github.com/x/y@1.9.1")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if ref.Version != "v1.9.1" {
		t.Errorf("Version = %q, ожидалось v1.9.1", ref.Version)
	}
}

func TestInvalidEntriesCarryExpectedFormat(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	cases := map[string]string{
		"pypi":  "requests-2.31.0", // нет ==
		"npm":   "lodash",          // нет версии
		"go":    "github.com/x/y",  // нет @
		"nuget": "Newtonsoft.Json", // нет @
	}
	for manager, entry := range cases {
		_, err := registry.ParseEntry(pluginFor(t, manager, f), entry)
		if err == nil {
			t.Errorf("%s: запись %q принята", manager, entry)
			continue
		}
		var formatErr *registry.InvalidFormatError
		if !errors.As(err, &formatErr) {
			t.Errorf("%s: err = %T, ожидалась InvalidFormatError", manager, err)
			continue
		}
		if formatErr.ExpectedFormat == "" {
			t.Errorf("%s: ожидаемый формат не приложен — сообщение бесполезно в интерфейсе", manager)
		}
	}
}

func TestInvalidVersionsRejected(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	cases := map[string]string{
		"pypi":  "requests==не-версия",
		"npm":   "lodash@^4.17.21", // диапазон, а не версия
		"go":    "github.com/x/y@master",
		"nuget": "Newtonsoft.Json@latest",
	}
	for manager, entry := range cases {
		if _, err := registry.ParseEntry(pluginFor(t, manager, f), entry); err == nil {
			t.Errorf("%s: запись %q с недопустимой версией принята", manager, entry)
		}
	}
}

// TestUnknownManager — менеджер, которого нет, обязан называть себя в ошибке.
//
// Сообщение «менеджер не поддерживается» без имени бесполезно ровно там, где
// нужно: при опечатке в коде менеджера (docekr вместо docker) оно не
// подсказывает, что искать.
func TestUnknownManager(t *testing.T) {
	r := registry.New(registry.Config{})
	_, err := r.Get("docekr")
	if err == nil {
		t.Fatal("несуществующий менеджер отдан как поддерживаемый")
	}
	if !strings.Contains(err.Error(), "docekr") {
		t.Errorf("ошибка не называет менеджер: %v", err)
	}
	// Полнота набора проверяется отдельно, сверкой с domain.ManagerCodes —
	// см. TestEveryManagerCodeHasPlugin. Числа здесь намеренно нет: оно
	// устаревало бы при каждом новом менеджере, ничего при этом не проверяя.
}

// --------------------------------------------------------------------- метаданные

func TestPyPIMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://pypi.test/pypi/six/1.16.0/json": `{
		  "info": {"license": "MIT", "classifiers": ["License :: OSI Approved :: MIT License"]},
		  "urls": [
		    {"packagetype": "sdist", "url": "https://files.test/six-1.16.0.tar.gz",
		     "filename": "six-1.16.0.tar.gz", "size": 34000,
		     "upload_time_iso_8601": "2021-05-05T14:18:17.000000Z",
		     "digests": {"sha256": "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"}},
		    {"packagetype": "bdist_wheel", "python_version": "py2.py3",
		     "url": "https://files.test/six-1.16.0-py2.py3-none-any.whl",
		     "filename": "six-1.16.0-py2.py3-none-any.whl", "size": 11000,
		     "upload_time_iso_8601": "2021-05-05T14:18:15.000000Z",
		     "digests": {"sha256": "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"}}
		  ]
		}`,
	}}
	p := pluginFor(t, "pypi", f)
	ref, err := registry.ParseEntry(p, "six==1.16.0")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}

	// Предпочитается wheel — он же публикуется во внутренний репозиторий.
	if meta.ArtifactFilename != "six-1.16.0-py2.py3-none-any.whl" {
		t.Errorf("ArtifactFilename = %q, ожидался wheel", meta.ArtifactFilename)
	}
	if meta.ChecksumAlgo != "sha256" || !strings.HasPrefix(meta.Checksum, "8abb2f1d") {
		t.Errorf("контрольная сумма = %s/%s", meta.ChecksumAlgo, meta.Checksum)
	}
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("LicenseSPDX = %q", meta.LicenseSPDX)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Year() != 2021 {
		t.Errorf("PublishedAt = %v", meta.PublishedAt)
	}
}

// TestPyPILicenseFromClassifiers — поле license пустое, лицензия есть только в
// classifiers.
func TestPyPILicenseFromClassifiers(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://pypi.test/pypi/pkg/1.0.0/json": `{
		  "info": {"license": "", "classifiers": ["License :: OSI Approved :: Apache Software License"]},
		  "urls": [{"packagetype": "sdist", "url": "u", "filename": "f", "digests": {}}]
		}`,
	}}
	p := pluginFor(t, "pypi", f)
	ref, _ := registry.ParseEntry(p, "pkg==1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if meta.LicenseSPDX != "Apache-2.0" {
		t.Errorf("LicenseSPDX = %q, ожидалось Apache-2.0 из classifiers", meta.LicenseSPDX)
	}
}

func TestPyPIMissingIsErrNotFound(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	p := pluginFor(t, "pypi", f)
	ref, _ := registry.ParseEntry(p, "нетакого==1.0.0")
	_, err := p.FetchMetadata(context.Background(), ref)
	if !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("err = %v, ожидалась ErrNotFound", err)
	}
}

func TestNpmMetadataAndIntegrity(t *testing.T) {
	// integrity = sha512-<base64>; base64("abc") = YWJj -> hex 616263.
	f := &fakeRegistry{responses: map[string]string{
		"https://npm.test/lodash": `{
		  "time": {"4.17.21": "2021-02-20T15:42:16.891Z"},
		  "versions": {"4.17.21": {
		    "license": "MIT",
		    "dist": {"tarball": "https://npm.test/lodash/-/lodash-4.17.21.tgz",
		             "integrity": "sha512-YWJj", "shasum": "deadbeef", "unpackedSize": 1400}
		  }}
		}`,
	}}
	p := pluginFor(t, "npm", f)
	ref, _ := registry.ParseEntry(p, "lodash@4.17.21")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.ArtifactFilename != "lodash-4.17.21.tgz" {
		t.Errorf("ArtifactFilename = %q", meta.ArtifactFilename)
	}
	// integrity предпочтительнее устаревшего shasum.
	if meta.ChecksumAlgo != "sha512" || meta.Checksum != "616263" {
		t.Errorf("checksum = %s/%s, ожидался sha512 из integrity", meta.ChecksumAlgo, meta.Checksum)
	}
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("LicenseSPDX = %q", meta.LicenseSPDX)
	}
	if meta.PublishedAt == nil {
		t.Error("PublishedAt не разобран — карантин посчитается пропущенным")
	}
}

// TestNpmLicenseAsObject — поле license бывает и объектом {"type": "..."}.
func TestNpmLicenseAsObject(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://npm.test/old-pkg": `{
		  "time": {"1.0.0": "2015-01-01T00:00:00.000Z"},
		  "versions": {"1.0.0": {"license": {"type": "ISC"}, "dist": {"tarball": "https://t/x-1.0.0.tgz"}}}
		}`,
	}}
	p := pluginFor(t, "npm", f)
	ref, _ := registry.ParseEntry(p, "old-pkg@1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if meta.LicenseSPDX != "ISC" {
		t.Errorf("LicenseSPDX = %q, лицензия-объект не разобрана", meta.LicenseSPDX)
	}
}

func TestNpmDeprecatedLicensesArray(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://npm.test/dual": `{
		  "time": {"1.0.0": "2015-01-01T00:00:00.000Z"},
		  "versions": {"1.0.0": {
		    "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}],
		    "dist": {"tarball": "https://t/dual-1.0.0.tgz"}
		  }}
		}`,
	}}
	p := pluginFor(t, "npm", f)
	ref, _ := registry.ParseEntry(p, "dual@1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if meta.LicenseSPDX != "Apache-2.0 OR MIT" {
		t.Errorf("LicenseSPDX = %q, ожидались обе лицензии", meta.LicenseSPDX)
	}
}

// TestNpmMissingVersionIsNotFound — пакет есть, версии нет: чаще всего опечатка
// в версии, и сообщение обязано это различать.
func TestNpmMissingVersionIsNotFound(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://npm.test/lodash": `{"time": {}, "versions": {"4.17.21": {"dist": {}}}}`,
	}}
	p := pluginFor(t, "npm", f)
	ref, _ := registry.ParseEntry(p, "lodash@9.9.9")
	_, err := p.FetchMetadata(context.Background(), ref)
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, ожидалась ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "версия") {
		t.Errorf("err = %v — не отличает отсутствие версии от отсутствия пакета", err)
	}
}

func TestNpmScopedNameEscapedInURL(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://npm.test/@babel%2fcore": `{
		  "time": {"7.24.0": "2024-02-01T00:00:00.000Z"},
		  "versions": {"7.24.0": {"license": "MIT", "dist": {"tarball": "https://t/core-7.24.0.tgz"}}}
		}`,
	}}
	p := pluginFor(t, "npm", f)
	ref, _ := registry.ParseEntry(p, "@babel/core@7.24.0")
	if _, err := p.FetchMetadata(context.Background(), ref); err != nil {
		t.Fatalf("scoped-имя не экранировано в адресе: %v", err)
	}
}

func TestGoMetadataEscapesUppercase(t *testing.T) {
	// Заглавные в пути модуля кодируются как !x.
	f := &fakeRegistry{responses: map[string]string{
		"https://goproxy.test/github.com/!sirupsen/logrus/@v/v1.9.3.info":    `{"Version":"v1.9.3","Time":"2023-06-01T10:00:00Z"}`,
		"https://goproxy.test/github.com/!sirupsen/logrus/@v/v1.9.3.ziphash": `h1:abcdef==`,
	}}
	p := pluginFor(t, "go", f)
	ref, _ := registry.ParseEntry(p, "github.com/Sirupsen/logrus@v1.9.3")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if !strings.Contains(meta.ArtifactURL, "!sirupsen") {
		t.Errorf("ArtifactURL = %q — заглавные буквы не экранированы", meta.ArtifactURL)
	}
	if meta.ChecksumAlgo != "h1" {
		t.Errorf("ChecksumAlgo = %q", meta.ChecksumAlgo)
	}
	if meta.PublishedAt == nil {
		t.Error("PublishedAt не разобран")
	}
	// go module proxy лицензию не отдаёт — её определяет юрист.
	if meta.LicenseSPDX != "" {
		t.Errorf("LicenseSPDX = %q, у go она не приходит из реестра", meta.LicenseSPDX)
	}
}

// TestGoMissingZiphashIsNotFatal — отсутствие ziphash не повод валить шаг:
// sha256 скачанного артефакта считается в любом случае.
func TestGoMissingZiphashIsNotFatal(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://goproxy.test/github.com/x/y/@v/v1.0.0.info": `{"Version":"v1.0.0","Time":"2023-01-01T00:00:00Z"}`,
	}}
	p := pluginFor(t, "go", f)
	ref, _ := registry.ParseEntry(p, "github.com/x/y@v1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("отсутствие ziphash уронило шаг: %v", err)
	}
	if meta.Checksum != "" {
		t.Errorf("Checksum = %q, ожидалась пустая", meta.Checksum)
	}
}

func TestGoLicenseFromPkgGoDev(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://goproxy.test/github.com/x/y/@v/v1.0.0.info": `{"Version":"v1.0.0","Time":"2023-01-01T00:00:00Z"}`,
		"https://pkg.test/github.com/x/y@v1.0.0?tab=licenses": `<html>
		  <div id="#lic-0">MIT, Apache-2.0</div>
		</html>`,
	}}
	r := registry.New(registry.Config{
		GoProxy: "https://goproxy.test", GoLicenseURL: "https://pkg.test", HTTP: f,
	})
	p, _ := r.Get("go")
	ref, _ := registry.ParseEntry(p, "github.com/x/y@v1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if meta.LicenseSPDX != "Apache-2.0 OR MIT" {
		t.Errorf("LicenseSPDX = %q, лицензии pkg.go.dev не разобраны", meta.LicenseSPDX)
	}
}

func TestRegistryRequestsHaveUserAgent(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://pypi.test/pypi/pkg/1.0.0/json": `{"info":{},"urls":[]}`,
	}}
	p := pluginFor(t, "pypi", f)
	ref, _ := registry.ParseEntry(p, "pkg==1.0.0")
	if _, err := p.FetchMetadata(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if len(f.seenHeaders) == 0 || f.seenHeaders[0].Get("User-Agent") != "pt-license-fetcher/1.0" {
		t.Errorf("User-Agent = %q", f.seenHeaders[0].Get("User-Agent"))
	}
}

func TestNuGetMetadata(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://nuget.test/v3/registration5-semver1/newtonsoft.json/13.0.3.json": `{
		  "catalogEntry": {"published": "2023-03-08T00:00:00Z", "licenseExpression": "MIT", "listed": true},
		  "packageContent": "https://nuget.test/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
		}`,
	}}
	p := pluginFor(t, "nuget", f)
	ref, _ := registry.ParseEntry(p, "Newtonsoft.Json@13.0.3")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("LicenseSPDX = %q", meta.LicenseSPDX)
	}
	if meta.ArtifactFilename != "newtonsoft.json.13.0.3.nupkg" {
		t.Errorf("ArtifactFilename = %q", meta.ArtifactFilename)
	}
	if meta.Yanked {
		t.Error("listed=true прочитано как отозванный пакет")
	}
}

// TestNuGetCatalogEntryAsLink — catalogEntry бывает ссылкой вместо объекта.
func TestNuGetCatalogEntryAsLink(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://nuget.test/v3/registration5-semver1/pkg/1.0.0.json": `{
		  "catalogEntry": "https://nuget.test/catalog/pkg/1.0.0.json"
		}`,
		"https://nuget.test/catalog/pkg/1.0.0.json": `{
		  "published": "2020-01-01T00:00:00Z", "licenseExpression": "Apache-2.0", "listed": false
		}`,
	}}
	p := pluginFor(t, "nuget", f)
	ref, _ := registry.ParseEntry(p, "Pkg@1.0.0")
	meta, err := p.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.LicenseSPDX != "Apache-2.0" {
		t.Errorf("LicenseSPDX = %q, каталог по ссылке не прочитан", meta.LicenseSPDX)
	}
	if !meta.Yanked {
		t.Error("listed=false не прочитано как отозванный пакет")
	}
	// Адрес артефакта достраивается, даже если packageContent нигде не пришёл.
	if !strings.Contains(meta.ArtifactURL, "v3-flatcontainer") {
		t.Errorf("ArtifactURL = %q", meta.ArtifactURL)
	}
}

// --------------------------------------------------------------------- команды установки

func TestInstallCommands(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	cases := map[string]struct{ entry, contains string }{
		"pypi":  {"requests==2.31.0", "pip install -i https://art.test/repository/pypi-internal/simple requests==2.31.0"},
		"npm":   {"lodash@4.17.21", "npm i --registry=https://art.test/repository/npm-internal/ lodash@4.17.21"},
		"go":    {"github.com/x/y@v1.0.0", "GOPROXY=https://art.test/repository/go-internal"},
		"nuget": {"Pkg@1.0.0", "dotnet add package Pkg -v 1.0.0"},
	}
	for manager, c := range cases {
		p := pluginFor(t, manager, f)
		ref, err := registry.ParseEntry(p, c.entry)
		if err != nil {
			t.Fatalf("%s: %v", manager, err)
		}
		got := p.InstallCommand(ref, "https://art.test", manager+"-internal")
		if !strings.Contains(got, c.contains) {
			t.Errorf("%s: InstallCommand = %q, ожидалось вхождение %q", manager, got, c.contains)
		}
	}
}

func TestOSVEcosystems(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{}}
	want := map[string]string{"pypi": "PyPI", "npm": "npm"}
	for manager, ecosystem := range want {
		if got := pluginFor(t, manager, f).OSVEcosystem(); got != ecosystem {
			t.Errorf("%s: OSVEcosystem = %q, ожидалось %q", manager, got, ecosystem)
		}
	}
	for _, manager := range []string{
		"go", "nuget", "maven", "docker", "conan", "luarocks", "terraform", "php", "git", "files",
	} {
		if got := pluginFor(t, manager, f).OSVEcosystem(); got != "" {
			t.Errorf("%s: OSV должен быть отключён, получена экосистема %q", manager, got)
		}
	}
}

// --------------------------------------------------------------------- SPDX

func TestNormalizeSPDX(t *testing.T) {
	cases := map[string]string{
		"MIT":                         "MIT",
		"mit license":                 "MIT",
		"Apache License, Version 2.0": "Apache-2.0",
		"https://www.apache.org/licenses/LICENSE-2.0.txt": "Apache-2.0",
		"BSD":               "BSD-3-Clause",
		"MIT OR Apache-2.0": "MIT OR Apache-2.0", // составное оставляем как есть
		"":                  "",
		"UNKNOWN":           "",
		"see license":       "",
		strings.Repeat("текст лицензии ", 30): "", // текст вместо идентификатора
	}
	for input, want := range cases {
		if got := registry.NormalizeSPDX(input); got != want {
			t.Errorf("NormalizeSPDX(%.30q) = %q, ожидалось %q", input, got, want)
		}
	}
}

// TestUnknownLicenseIsNotAnIdentifier — «unknown» в поле SPDX прошло бы сверку
// со справочником как обычное имя лицензии и молча уехало бы мимо юриста.
func TestUnknownLicenseIsNotAnIdentifier(t *testing.T) {
	for _, value := range []string{"unknown", "None", "UNLICENSED", "Other/Proprietary License"} {
		if got := registry.NormalizeSPDX(value); got != "" {
			t.Errorf("NormalizeSPDX(%q) = %q — пакет проскочил бы мимо юриста", value, got)
		}
	}
}

func TestEscapeModule(t *testing.T) {
	if got := registry.EscapeModule("github.com/Sirupsen/Logrus"); got != "github.com/!sirupsen/!logrus" {
		t.Errorf("EscapeModule = %q", got)
	}
	if got := registry.EscapeModule("github.com/x/y"); got != "github.com/x/y" {
		t.Errorf("EscapeModule изменил путь без заглавных: %q", got)
	}
}
