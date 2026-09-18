package requests_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"moderation/internal/db"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
	"moderation/internal/resolve"
)

// Разбор и раскрытие проверяются на настоящем Postgres: половина их работы —
// сверка с базой (что уже одобрено, что заводится впервые).

func mustRepo(t *testing.T) *repo.Repo {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	pool, err := db.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	return repo.New(pool)
}

// fakePyPI — реестр в памяти: пакет -> версия -> requires_dist.
type fakePyPI struct {
	packages map[string]map[string][]string
}

func (f *fakePyPI) Do(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	reply := func(status int, body string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)),
			Header: http.Header{}}, nil
	}
	if strings.HasPrefix(path, "/simple/") {
		name := strings.Trim(strings.TrimPrefix(path, "/simple/"), "/")
		versions, ok := f.packages[name]
		if !ok {
			return reply(http.StatusNotFound, `{}`)
		}
		var list []string
		for v := range versions {
			list = append(list, v)
		}
		sort.Strings(list)
		body, _ := json.Marshal(map[string]any{"versions": list})
		return reply(http.StatusOK, string(body))
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 && parts[0] == "pypi" && parts[3] == "json" {
		requires, ok := f.packages[parts[1]][parts[2]]
		if !ok {
			return reply(http.StatusNotFound, `{}`)
		}
		body, _ := json.Marshal(map[string]any{"info": map[string]any{"requires_dist": requires}})
		return reply(http.StatusOK, string(body))
	}
	return reply(http.StatusNotFound, `{}`)
}

// newService собирает сервис с фейковым реестром и настоящей базой.
func newService(t *testing.T, fake *fakePyPI, maxPackages int) *requests.Service {
	t.Helper()
	reg := registry.New(registry.Config{
		PyPIURL: "https://pypi.test", NpmURL: "https://npm.test",
		GoProxy: "https://goproxy.test", NuGetURL: "https://nuget.test",
		HTTP: fake,
	})
	return &requests.Service{
		Repo: mustRepo(t), Registry: reg,
		Limits:   requests.Limits{MaxPackages: maxPackages, MaxUploadSize: 1 << 20},
		Resolver: resolve.New(reg, resolve.DefaultOptions(), nil),
	}
}

// uniq — суффикс, чтобы прогоны не цеплялись друг за друга в общей базе.
func uniq() string { return fmt.Sprintf("t%d", time.Now().UnixNano()%1_000_000_000) }

func parsedNames(result requests.ParseResult) []string {
	var out []string
	for _, pkg := range result.Packages {
		if pkg.Ref == nil {
			continue
		}
		out = append(out, fmt.Sprintf("%s==%s@%d", pkg.Ref.Name, pkg.Ref.Version, pkg.Depth))
	}
	sort.Strings(out)
	return out
}

// poetry.lock перечисляет закрытый набор и НЕ различает прямые и
// транзитивные. Пока такие записи считались транзитивными, заявка по этому
// файлу без галочки приезжала пустой: фильтр выбрасывал весь файл.
func TestLockFileWithoutKindIsNotDroppedWholesale(t *testing.T) {
	service := newService(t, &fakePyPI{}, 50)
	content := []byte(`
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.1.0"
`)
	result, err := service.Parse(context.Background(), requests.Input{
		Manager: "pypi", Filename: "poetry.lock", Content: content, IncludeTransitive: false,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(result.New()) != 2 {
		t.Fatalf("принято %d записей, ожидалось 2: %v", len(result.New()), parsedNames(result))
	}
	for _, pkg := range result.Packages {
		if pkg.DependencyKind != "direct" {
			t.Errorf("%s помечен как %q, а формат роли не различает", pkg.Raw, pkg.DependencyKind)
		}
	}
	joined := strings.Join(result.Warnings, " ")
	if !strings.Contains(joined, "не различает прямые и транзитивные") {
		t.Fatalf("пользователь не предупреждён о формате: %v", result.Warnings)
	}
}

// А там, где формат роли различает, фильтр обязан работать по-прежнему.
func TestPackageLockKeepsOnlyDirectWithoutFlag(t *testing.T) {
	service := newService(t, &fakePyPI{}, 50)
	content := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"dependencies": {"express": "^4.18.2"}},
	    "node_modules/express": {"version": "4.18.2"},
	    "node_modules/body-parser": {"version": "1.20.1"}
	  }
	}`)
	result, err := service.Parse(context.Background(), requests.Input{
		Manager: "npm", Filename: "package-lock.json", Content: content,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(result.New()) != 1 || result.New()[0].Ref.Name != "express" {
		t.Fatalf("без галочки должна остаться одна прямая зависимость: %v", parsedNames(result))
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "пропущены") {
		t.Fatalf("о пропущенных транзитивных не сказано: %v", result.Warnings)
	}
}

func TestExpandAddsTransitiveWithParents(t *testing.T) {
	suffix := uniq()
	root := "exp-root-" + suffix
	mid := "exp-mid-" + suffix
	leaf := "exp-leaf-" + suffix
	fake := &fakePyPI{packages: map[string]map[string][]string{
		root: {"1.0.0": {mid + " (>=2.0)"}},
		mid:  {"2.0.0": nil, "2.4.0": {leaf + " (>=1.0)"}},
		leaf: {"1.0.0": nil, "1.5.0": nil},
	}}
	service := newService(t, fake, 50)

	parsed, err := service.Parse(context.Background(), requests.Input{
		Manager: "pypi", Entries: []string{root + "==1.0.0"},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	expanded, walk, err := service.Expand(context.Background(), parsed,
		resolve.Options{MaxDepth: 3, MaxNodes: 50, Concurrency: 4})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if walk == nil {
		t.Fatal("итог обхода потерян — по нему заявка объясняет, полное ли дерево")
	}

	got := parsedNames(expanded)
	// parsedNames сортирует, поэтому ожидание тоже в алфавитном порядке.
	want := []string{
		fmt.Sprintf("%s==1.5.0@2", leaf),
		fmt.Sprintf("%s==2.4.0@1", mid),
		fmt.Sprintf("%s==1.0.0@0", root),
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("дерево = %v, ожидалось %v", got, want)
	}

	for _, pkg := range expanded.Packages {
		if pkg.Depth == 0 {
			continue
		}
		if pkg.DependencyKind != "transitive" {
			t.Errorf("%s: вид зависимости %q", pkg.Raw, pkg.DependencyKind)
		}
		if pkg.ParentKey == "" || pkg.RequiredRange == "" {
			t.Errorf("%s: потеряна связь с родителем (%q / %q)", pkg.Raw, pkg.ParentKey, pkg.RequiredRange)
		}
	}
	if !strings.Contains(strings.Join(expanded.Warnings, " "), "раскрыты по данным реестра") {
		t.Fatalf("автор не предупреждён о раскрытии: %v", expanded.Warnings)
	}
}

// «Менеджер так не умеет» и «зависимостей нет» выглядят одинаково — пустым
// деревом. Отличать их обязано предупреждение.
func TestExpandNamesUnsupportedManager(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{}}
	service := newService(t, fake, 50)
	parsed := requests.ParseResult{Manager: "maven"}

	expanded, walk, err := service.Expand(context.Background(), parsed, resolve.DefaultOptions())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if walk != nil {
		t.Fatal("обхода не было — итога быть не должно")
	}
	if !strings.Contains(strings.Join(expanded.Warnings, " "), "не умеет раскрывать зависимости") {
		t.Fatalf("молчаливое пустое дерево: %v", expanded.Warnings)
	}
}

// Предел заявки главнее предела обхода, и об обрезке нельзя молчать:
// неполное дерево выглядит точно так же, как полное.
func TestExpandRespectsRequestLimitAndSaysSo(t *testing.T) {
	suffix := uniq()
	root := "lim-root-" + suffix
	packages := map[string]map[string][]string{}
	var requires []string
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("lim-dep%02d-%s", i, suffix)
		requires = append(requires, name)
		packages[name] = map[string][]string{"1.0.0": nil}
	}
	packages[root] = map[string][]string{"1.0.0": requires}
	service := newService(t, &fakePyPI{packages: packages}, 4)

	parsed, err := service.Parse(context.Background(), requests.Input{
		Manager: "pypi", Entries: []string{root + "==1.0.0"},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	expanded, walk, err := service.Expand(context.Background(), parsed,
		resolve.Options{MaxDepth: 3, MaxNodes: 100, Concurrency: 4})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !walk.Truncated {
		t.Fatal("предел заявки (4) меньше дерева (13) — обход обязан был обрезаться")
	}
	if len(expanded.New()) > 4 {
		t.Fatalf("заведено %d пакетов при пределе 4", len(expanded.New()))
	}
	if !strings.Contains(strings.Join(expanded.Warnings, " "), "обрезано по пределу") {
		t.Fatalf("об обрезке не сказано: %v", expanded.Warnings)
	}
}

// Конфликт версий не решается за разработчика, но и не замалчивается.
func TestExpandNamesVersionConflict(t *testing.T) {
	suffix := uniq()
	root := "cnf-root-" + suffix
	left, right, shared := "cnf-left-"+suffix, "cnf-right-"+suffix, "cnf-shared-"+suffix
	fake := &fakePyPI{packages: map[string]map[string][]string{
		root:   {"1.0.0": {left, right}},
		left:   {"1.0.0": {shared + " (==1.0.0)"}},
		right:  {"1.0.0": {shared + " (==2.0.0)"}},
		shared: {"1.0.0": nil, "2.0.0": nil},
	}}
	service := newService(t, fake, 50)

	parsed, err := service.Parse(context.Background(), requests.Input{
		Manager: "pypi", Entries: []string{root + "==1.0.0"},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	expanded, _, err := service.Expand(context.Background(), parsed,
		resolve.Options{MaxDepth: 3, MaxNodes: 50, Concurrency: 4})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	joined := strings.Join(expanded.Warnings, " ")
	if !strings.Contains(joined, "затребован в разных версиях") {
		t.Fatalf("конфликт версий замолчан: %v", expanded.Warnings)
	}
	if !strings.Contains(joined, "1.0.0, 2.0.0") {
		t.Fatalf("в предупреждении нет самих версий: %v", expanded.Warnings)
	}
}

// Нераскрытая зависимость обязана быть названа: «не смогли» — это не «нет».
func TestExpandNamesUnresolved(t *testing.T) {
	suffix := uniq()
	root := "unr-root-" + suffix
	fake := &fakePyPI{packages: map[string]map[string][]string{
		root: {"1.0.0": {"unr-missing-" + suffix + " (>=1.0)"}},
	}}
	service := newService(t, fake, 50)

	parsed, err := service.Parse(context.Background(), requests.Input{
		Manager: "pypi", Entries: []string{root + "==1.0.0"},
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	expanded, walk, err := service.Expand(context.Background(), parsed,
		resolve.Options{MaxDepth: 2, MaxNodes: 50, Concurrency: 2})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(walk.Problems) != 1 {
		t.Fatalf("проблем %d, ожидалась 1: %+v", len(walk.Problems), walk.Problems)
	}
	if !strings.Contains(strings.Join(expanded.Warnings, " "), "Не удалось раскрыть зависимости") {
		t.Fatalf("нераскрытая зависимость замолчана: %v", expanded.Warnings)
	}
}
