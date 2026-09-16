package depfile

import (
	"sort"
	"strings"
	"testing"
)

// Файлы в тестах — настоящего вида, а не сокращённые до одной строки: почти
// все ошибки разбора здесь про то, что реальный файл сложнее выдуманного
// (вложенные ItemGroup, scoped-пакеты npm, комментарии, директивы).

func find(deps []RawDependency, name string) (RawDependency, bool) {
	for _, d := range deps {
		if d.Name == name {
			return d, true
		}
	}
	return RawDependency{}, false
}

func names(deps []RawDependency) []string {
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

func mustParse(t *testing.T, manager, filename, content string) []RawDependency {
	t.Helper()
	deps, err := Parse(manager, filename, []byte(content))
	if err != nil {
		t.Fatalf("%s/%s: %v", manager, filename, err)
	}
	return deps
}

// ---------------------------------------------------------------- python

func TestRequirementsTxt(t *testing.T) {
	deps := mustParse(t, "pypi", "requirements.txt", `
# комментарий
requests==2.31.0
Django[argon2]==5.0.1
urllib3>=2.0            # диапазон — версию не берём
-r base.txt
--hash=sha256:deadbeef
https://example.com/pkg.tar.gz
six==1.16.0 --hash=sha256:abc
`)
	if got, want := len(deps), 4; got != want {
		t.Fatalf("записей %d, ожидалось %d: %+v", got, want, names(deps))
	}
	if d, _ := find(deps, "requests"); d.Version != "2.31.0" || d.Kind != KindDirect {
		t.Errorf("requests: %+v", d)
	}
	// Extras не мешают: имя берётся без них.
	if d, ok := find(deps, "Django"); !ok || d.Version != "5.0.1" {
		t.Errorf("Django с extras: %+v", d)
	}
	// Хеши в той же строке не должны попадать в версию.
	if d, _ := find(deps, "six"); d.Version != "1.16.0" {
		t.Errorf("six с --hash: %+v", d)
	}
	// Незакреплённая версия не отбрасывается молча: пользователь должен
	// увидеть, что именно не взяли.
	d, _ := find(deps, "urllib3")
	if d.Version != "" || d.Note == "" {
		t.Errorf("urllib3 должен вернуться с объяснением: %+v", d)
	}
}

func TestRequirementsTxtRejectsGarbage(t *testing.T) {
	_, err := Parse("pypi", "requirements.txt", []byte("!!! это не строка зависимости"))
	if err == nil {
		t.Fatal("мусор в файле должен быть ошибкой формата, а не пустым списком")
	}
	var invalid *InvalidFormatError
	if !asInvalid(err, &invalid) {
		t.Fatalf("ожидалась ошибка формата, получено %T", err)
	}
}

func TestPoetryLockIsTransitive(t *testing.T) {
	deps := mustParse(t, "pypi", "poetry.lock", `
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP for Humans"

[[package]]
name = "urllib3"
version = "2.1.0"
`)
	if len(deps) != 2 {
		t.Fatalf("записей %d: %v", len(deps), names(deps))
	}
	// poetry.lock не различает прямые и транзитивные — прямые перечислены в
	// pyproject.toml, поэтому здесь всё транзитивное.
	for _, d := range deps {
		if d.Kind != KindTransitive {
			t.Errorf("%s должен быть transitive: %+v", d.Name, d)
		}
	}
}

func TestPyprojectToml(t *testing.T) {
	deps := mustParse(t, "pypi", "pyproject.toml", `
[project]
name = "app"
dependencies = ["requests==2.31.0", "urllib3>=2.0"]

[project.optional-dependencies]
dev = ["pytest==8.0.0"]

[tool.poetry.dependencies]
python = "^3.12"
httpx = "==0.27.0"
attrs = { version = "23.2.0" }
loose = "^1.0"
`)
	for _, want := range []struct{ name, version string }{
		{"requests", "2.31.0"}, {"pytest", "8.0.0"}, {"httpx", "0.27.0"}, {"attrs", "23.2.0"},
	} {
		d, ok := find(deps, want.name)
		if !ok || d.Version != want.version {
			t.Errorf("%s: %+v, ожидалась версия %s", want.name, d, want.version)
		}
	}
	// python — не пакет для модерации.
	if _, ok := find(deps, "python"); ok {
		t.Error("python из tool.poetry.dependencies не должен попадать в заявку")
	}
	for _, name := range []string{"urllib3", "loose"} {
		if d, _ := find(deps, name); d.Note == "" {
			t.Errorf("%s задан диапазоном — нужно объяснение: %+v", name, d)
		}
	}
}

// ---------------------------------------------------------------- npm

func TestPackageLockV3SeparatesDirect(t *testing.T) {
	deps := mustParse(t, "npm", "package-lock.json", `{
      "lockfileVersion": 3,
      "packages": {
        "": {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/jest": {"version": "29.7.0"},
        "node_modules/body-parser": {"version": "1.20.1"},
        "node_modules/@types/node": {"version": "20.11.0"},
        "node_modules/linked": {"link": true, "resolved": "../linked"}
      }
    }`)

	// Разделение прямых и транзитивных — не украшение: без него заявка на два
	// пакета превращается в заявку на весь lock-файл.
	if d, _ := find(deps, "express"); d.Kind != KindDirect {
		t.Errorf("express объявлен в корне — direct: %+v", d)
	}
	if d, _ := find(deps, "jest"); d.Kind != KindDirect {
		t.Errorf("jest из devDependencies — direct: %+v", d)
	}
	if d, _ := find(deps, "body-parser"); d.Kind != KindTransitive {
		t.Errorf("body-parser не объявлен в корне — transitive: %+v", d)
	}
	// Scoped-пакет должен сохранить @scope/ в имени.
	if d, ok := find(deps, "@types/node"); !ok || d.Version != "20.11.0" {
		t.Errorf("scoped-пакет разобран неверно: %+v", d)
	}
	// Локальная ссылка — не пакет из реестра.
	if _, ok := find(deps, "linked"); ok {
		t.Error("link-запись не должна попадать в заявку")
	}
}

func TestPackageLockV1(t *testing.T) {
	deps := mustParse(t, "npm", "package-lock.json", `{
      "lockfileVersion": 1,
      "dependencies": {
        "express": {"version": "4.18.2", "dependencies": {
          "body-parser": {"version": "1.20.1"}
        }}
      }
    }`)
	if d, ok := find(deps, "body-parser"); !ok || d.Kind != KindTransitive {
		t.Errorf("вложенная зависимость v1: %+v", d)
	}
	if len(deps) != 2 {
		t.Fatalf("записей %d: %v", len(deps), names(deps))
	}
}

func TestYarnLock(t *testing.T) {
	deps := mustParse(t, "npm", "yarn.lock", `
# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.20.0":
  version "7.23.9"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.9.tgz"

express@^4.18.0:
  version "4.18.2"
`)
	if d, ok := find(deps, "@babel/core"); !ok || d.Version != "7.23.9" {
		t.Errorf("scoped-пакет с несколькими спецификаторами: %+v", d)
	}
	if d, ok := find(deps, "express"); !ok || d.Version != "4.18.2" {
		t.Errorf("express: %+v", d)
	}
	if len(deps) != 2 {
		t.Fatalf("записей %d: %v", len(deps), names(deps))
	}
}

func TestPackageJSONRangesExplained(t *testing.T) {
	deps := mustParse(t, "npm", "package.json", `{
      "dependencies": {"express": "4.18.2", "lodash": "^4.17.21"},
      "devDependencies": {"jest": "29.7.0"}
    }`)
	if d, _ := find(deps, "express"); d.Version != "4.18.2" {
		t.Errorf("точная версия: %+v", d)
	}
	if d, _ := find(deps, "lodash"); d.Version != "" || !strings.Contains(d.Note, "диапазон") {
		t.Errorf("диапазон должен объясняться: %+v", d)
	}
}

// ---------------------------------------------------------------- go

func TestGoMod(t *testing.T) {
	deps := mustParse(t, "go", "go.mod", `module example.com/app

go 1.25

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/jackc/pgx/v5 v5.10.0 // indirect
)

require golang.org/x/crypto v0.44.0
`)
	if d, _ := find(deps, "github.com/go-chi/chi/v5"); d.Kind != KindDirect {
		t.Errorf("прямая зависимость: %+v", d)
	}
	if d, _ := find(deps, "github.com/jackc/pgx/v5"); d.Kind != KindTransitive {
		t.Errorf("// indirect означает transitive: %+v", d)
	}
	// Однострочный require вне блока тоже должен читаться.
	if d, ok := find(deps, "golang.org/x/crypto"); !ok || d.Version != "v0.44.0" {
		t.Errorf("однострочный require: %+v", d)
	}
}

// go.sum помечает всё прямым НАМЕРЕННО: формат не хранит признак прямой
// зависимости, а пометка transitive приводила к тому, что заявка без
// include_transitive отбрасывала весь файл и получалась пустой.
func TestGoSumMarksEverythingDirect(t *testing.T) {
	deps := mustParse(t, "go", "go.sum", `
github.com/go-chi/chi/v5 v5.3.2 h1:abc=
github.com/go-chi/chi/v5 v5.3.2/go.mod h1:def=
golang.org/x/sys v0.47.0 h1:ghi=
`)
	if len(deps) != 2 {
		t.Fatalf("записей %d: %v", len(deps), names(deps))
	}
	for _, d := range deps {
		if d.Kind != KindDirect {
			t.Errorf("%s: записи go.sum помечаются direct: %+v", d.Name, d)
		}
	}
	// /go.mod-строка не должна давать вторую запись той же версии.
	if d, _ := find(deps, "github.com/go-chi/chi/v5"); d.Version != "v5.3.2" {
		t.Errorf("версия из go.sum: %+v", d)
	}
}

func TestGoModRejectsForeignFile(t *testing.T) {
	if _, err := Parse("go", "go.mod", []byte("совсем не go.mod\n")); err == nil {
		t.Fatal("файл без module/require должен быть отвергнут")
	}
}

// ---------------------------------------------------------------- nuget

func TestCsprojNested(t *testing.T) {
	deps := mustParse(t, "nuget", "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
    <PackageReference Include="From.Variable" Version="$(SomeVersion)" />
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
  </ItemGroup>
</Project>`)

	// Элементы лежат внутри ItemGroup — разбор обязан заходить вглубь.
	if d, ok := find(deps, "Newtonsoft.Json"); !ok || d.Version != "13.0.3" {
		t.Errorf("атрибут Version: %+v", d)
	}
	if d, ok := find(deps, "Serilog"); !ok || d.Version != "3.1.1" {
		t.Errorf("вложенный <Version>: %+v", d)
	}
	if d, _ := find(deps, "From.Variable"); d.Version != "" || d.Note == "" {
		t.Errorf("подстановка MSBuild — нужно объяснение: %+v", d)
	}
	if d, _ := find(deps, "Ranged"); d.Version != "" || d.Note == "" {
		t.Errorf("диапазон — нужно объяснение: %+v", d)
	}
}

func TestPackagesConfig(t *testing.T) {
	deps := mustParse(t, "nuget", "packages.config", `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="NLog" version="5.2.8" />
</packages>`)
	if len(deps) != 2 {
		t.Fatalf("записей %d: %v", len(deps), names(deps))
	}
}

func TestPackagesLockJSON(t *testing.T) {
	deps := mustParse(t, "nuget", "packages.lock.json", `{
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
          "System.Buffers": {"type": "Transitive", "resolved": "4.5.1"},
          "MyLib": {"type": "Project"}
        }
      }
    }`)
	if d, _ := find(deps, "Newtonsoft.Json"); d.Kind != KindDirect || d.Version != "13.0.3" {
		t.Errorf("Direct: %+v", d)
	}
	if d, _ := find(deps, "System.Buffers"); d.Kind != KindTransitive {
		t.Errorf("Transitive: %+v", d)
	}
	// Project — ссылка на соседний проект решения, а не пакет из реестра.
	if _, ok := find(deps, "MyLib"); ok {
		t.Error("записи типа Project не должны попадать в заявку")
	}
}

// XML приходит от пользователя: внешние сущности разворачивать нельзя —
// иначе файл проекта может прочитать файл с диска сервиса.
func TestXMLExternalEntitiesNotExpanded(t *testing.T) {
	content := `<?xml version="1.0"?>
<!DOCTYPE packages [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<packages><package id="&xxe;" version="1.0.0" /></packages>`
	deps, err := Parse("nuget", "packages.config", []byte(content))
	if err != nil {
		return // отказ разбирать такой файл — тоже приемлемый исход
	}
	for _, d := range deps {
		if strings.Contains(d.Name, "root:") || strings.Contains(d.Name, "/bin/") {
			t.Fatalf("внешняя сущность развернулась: %+v", d)
		}
	}
}

func TestUnknownFilesRejected(t *testing.T) {
	cases := []struct{ manager, filename string }{
		{"pypi", "Gemfile.lock"},
		{"npm", "go.sum"},
		{"go", "package.json"},
		{"nuget", "requirements.txt"},
		{"maven", "pom.xml"},
	}
	for _, tc := range cases {
		if _, err := Parse(tc.manager, tc.filename, []byte("x")); err == nil {
			t.Errorf("%s/%s: файл чужого формата должен быть отвергнут", tc.manager, tc.filename)
		}
	}
}

// Путь к файлу на машине пользователя к делу не относится — берётся базовое имя.
func TestFilenameWithPath(t *testing.T) {
	deps := mustParse(t, "pypi", "/home/user/проект/requirements.txt", "requests==2.31.0\n")
	if len(deps) != 1 {
		t.Fatalf("записей %d", len(deps))
	}
	deps = mustParse(t, "npm", `C:\проект\package.json`, `{"dependencies":{"express":"4.18.2"}}`)
	if len(deps) != 1 {
		t.Fatalf("windows-путь: записей %d", len(deps))
	}
}

func asInvalid(err error, target **InvalidFormatError) bool {
	v, ok := err.(*InvalidFormatError)
	if ok {
		*target = v
	}
	return ok
}
