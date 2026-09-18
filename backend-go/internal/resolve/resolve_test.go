package resolve_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"moderation/internal/registry"
	"moderation/internal/resolve"
)

// fakePyPI — реестр pypi в памяти: пакет -> версия -> список requires_dist.
// Через него собираются деревья любой формы, включая циклические.
type fakePyPI struct {
	packages map[string]map[string][]string
	requests int64
}

func (f *fakePyPI) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(&f.requests, 1)
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
		body, _ := json.Marshal(map[string]any{"name": name, "versions": list})
		return reply(http.StatusOK, string(body))
	}

	// /pypi/{name}/{version}/json
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 && parts[0] == "pypi" && parts[3] == "json" {
		versions, ok := f.packages[parts[1]]
		if !ok {
			return reply(http.StatusNotFound, `{}`)
		}
		requires, ok := versions[parts[2]]
		if !ok {
			return reply(http.StatusNotFound, `{}`)
		}
		body, _ := json.Marshal(map[string]any{"info": map[string]any{"requires_dist": requires}})
		return reply(http.StatusOK, string(body))
	}
	return reply(http.StatusNotFound, `{}`)
}

func rootRef(t *testing.T, reg *registry.Registry, manager, name, version string) registry.Ref {
	t.Helper()
	plugin, err := reg.Get(manager)
	if err != nil {
		t.Fatalf("Get(%q): %v", manager, err)
	}
	ref, err := registry.MakeRef(plugin, name, version)
	if err != nil {
		t.Fatalf("MakeRef: %v", err)
	}
	return ref
}

func walk(t *testing.T, fake *fakePyPI, opts resolve.Options, name, version string) resolve.Result {
	t.Helper()
	reg := registry.New(registry.Config{
		PyPIURL: "https://pypi.test", NpmURL: "https://npm.test",
		GoProxy: "https://goproxy.test", NuGetURL: "https://nuget.test",
		HTTP: fake,
	})
	r := resolve.New(reg, opts, nil)
	result, err := r.Walk(context.Background(), "pypi", []registry.Ref{rootRef(t, reg, "pypi", name, version)})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return result
}

func names(result resolve.Result) []string {
	var out []string
	for _, node := range result.Nodes {
		out = append(out, fmt.Sprintf("%s==%s@%d", node.Ref.Name, node.Ref.Version, node.Depth))
	}
	sort.Strings(out)
	return out
}

func TestWalkBuildsTree(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"root": {"1.0.0": {"mid (>=2.0)", "leaf (>=1.0)"}},
		"mid":  {"2.0.0": {"leaf (>=1.2)"}, "2.1.0": {"leaf (>=1.2)"}},
		"leaf": {"1.0.0": nil, "1.3.0": nil},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 3, MaxNodes: 50, Concurrency: 4}, "root", "1.0.0")

	got := names(result)
	want := []string{"leaf==1.3.0@1", "mid==2.1.0@1", "root==1.0.0@0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("дерево = %v, ожидалось %v", got, want)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("проблем быть не должно: %+v", result.Problems)
	}
	// leaf затребован и корнем, и mid — узел один, родителей двое.
	for _, node := range result.Nodes {
		if node.Ref.Name == "leaf" && len(node.Parents) != 2 {
			t.Fatalf("у leaf родителей %d, ожидалось 2: %+v", len(node.Parents), node.Parents)
		}
	}
}

func TestWalkRespectsDepth(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"a": {"1.0.0": {"b"}},
		"b": {"1.0.0": {"c"}},
		"c": {"1.0.0": {"d"}},
		"d": {"1.0.0": nil},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 1, MaxNodes: 50, Concurrency: 2}, "a", "1.0.0")
	if got := names(result); strings.Join(got, ",") != "a==1.0.0@0,b==1.0.0@1" {
		t.Fatalf("глубина 1 дала %v", got)
	}

	deep := walk(t, fake, resolve.Options{MaxDepth: 2, MaxNodes: 50, Concurrency: 2}, "a", "1.0.0")
	if got := names(deep); strings.Join(got, ",") != "a==1.0.0@0,b==1.0.0@1,c==1.0.0@2" {
		t.Fatalf("глубина 2 дала %v", got)
	}
	if deep.MaxDepth != 2 {
		t.Fatalf("MaxDepth = %d, ожидалось 2", deep.MaxDepth)
	}
}

// Цикл a -> b -> a встречается в настоящих реестрах и не должен зацикливать
// обход: узел, который уже в дереве, второй раз не раскрывается.
func TestWalkSurvivesCycle(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"a": {"1.0.0": {"b"}},
		"b": {"1.0.0": {"a"}},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 10, MaxNodes: 50, Concurrency: 2}, "a", "1.0.0")
	if got := names(result); strings.Join(got, ",") != "a==1.0.0@0,b==1.0.0@1" {
		t.Fatalf("цикл дал %v", got)
	}
}

func TestWalkTruncatesAtLimit(t *testing.T) {
	packages := map[string]map[string][]string{"root": {"1.0.0": {}}}
	var requires []string
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("dep%02d", i)
		requires = append(requires, name)
		packages[name] = map[string][]string{"1.0.0": nil}
	}
	packages["root"] = map[string][]string{"1.0.0": requires}

	fake := &fakePyPI{packages: packages}
	result := walk(t, fake, resolve.Options{MaxDepth: 3, MaxNodes: 5, Concurrency: 4}, "root", "1.0.0")
	if !result.Truncated {
		t.Fatal("обход упёрся в предел, но Truncated не выставлен")
	}
	if len(result.Nodes) != 5 {
		t.Fatalf("узлов %d, ожидалось ровно 5 (предел)", len(result.Nodes))
	}
	if !strings.Contains(result.Summary(), "обрезано") {
		t.Fatalf("итог не говорит об обрезке: %s", result.Summary())
	}
}

func TestOptionalSkippedByDefault(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"root":       {"1.0.0": {"needed", "extra-only ; extra == 'socks'"}},
		"needed":     {"1.0.0": nil},
		"extra-only": {"1.0.0": nil},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 2, MaxNodes: 50, Concurrency: 2}, "root", "1.0.0")
	if got := names(result); strings.Join(got, ",") != "needed==1.0.0@1,root==1.0.0@0" {
		t.Fatalf("необязательная зависимость не должна раскрываться: %v", got)
	}

	withOptional := walk(t, fake, resolve.Options{MaxDepth: 2, MaxNodes: 50, Concurrency: 2,
		IncludeOptional: true}, "root", "1.0.0")
	if len(withOptional.Nodes) != 3 {
		t.Fatalf("с IncludeOptional ожидалось 3 узла, получено %v", names(withOptional))
	}
}

// Нераскрытая зависимость обязана быть названа: «резолвер не смог» не то же
// самое, что «зависимостей нет».
func TestUnresolvableIsReported(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"root":    {"1.0.0": {"missing (>=1.0)", "toonew (>=9.0)", "present"}},
		"toonew":  {"1.0.0": nil},
		"present": {"1.0.0": nil},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 2, MaxNodes: 50, Concurrency: 2}, "root", "1.0.0")

	if len(result.Problems) != 2 {
		t.Fatalf("проблем %d, ожидалось 2: %+v", len(result.Problems), result.Problems)
	}
	byName := map[string]string{}
	for _, problem := range result.Problems {
		byName[problem.Name] = problem.Reason
	}
	if !strings.Contains(byName["missing"], "не отдал версии") {
		t.Errorf("для отсутствующего пакета причина: %q", byName["missing"])
	}
	if !strings.Contains(byName["toonew"], "нет версии под требование") {
		t.Errorf("для недостижимого требования причина: %q", byName["toonew"])
	}
	if !strings.Contains(result.Summary(), "не раскрыто: 2") {
		t.Fatalf("итог молчит о проблемах: %s", result.Summary())
	}
}

func TestConflictingVersionsAreNamed(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{
		"root":   {"1.0.0": {"left", "right"}},
		"left":   {"1.0.0": {"shared (==1.0.0)"}},
		"right":  {"1.0.0": {"shared (==2.0.0)"}},
		"shared": {"1.0.0": nil, "2.0.0": nil},
	}}
	result := walk(t, fake, resolve.Options{MaxDepth: 3, MaxNodes: 50, Concurrency: 4}, "root", "1.0.0")
	if len(result.Conflicts) != 1 || result.Conflicts[0].Name != "shared" {
		t.Fatalf("конфликт версий не найден: %+v", result.Conflicts)
	}
	if strings.Join(result.Conflicts[0].Versions, ",") != "1.0.0,2.0.0" {
		t.Fatalf("версии конфликта: %v", result.Conflicts[0].Versions)
	}
	if !strings.Contains(result.Summary(), "конфликтов версий: 1") {
		t.Fatalf("итог молчит о конфликте: %s", result.Summary())
	}
}

// Один и тот же вход обязан давать один и тот же результат: иначе заявку
// невозможно сверить между прогонами, а параллельный обход именно это и
// ломает, если не упорядочить узлы.
func TestWalkIsDeterministic(t *testing.T) {
	// У каждого пакета первого уровня свой потомок: иначе порядок второго
	// уровня не от чего зависеть, и тест не заметил бы гонку.
	packages := map[string]map[string][]string{}
	var requires []string
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("pkg%02d", i)
		leaf := fmt.Sprintf("leaf%02d", i)
		requires = append(requires, name)
		packages[name] = map[string][]string{"1.0.0": {leaf, "common"}}
		packages[leaf] = map[string][]string{"1.0.0": nil}
	}
	packages["root"] = map[string][]string{"1.0.0": requires}
	packages["common"] = map[string][]string{"1.0.0": nil}

	first := ""
	for attempt := 0; attempt < 5; attempt++ {
		fake := &fakePyPI{packages: packages}
		result := walk(t, fake, resolve.Options{MaxDepth: 3, MaxNodes: 100, Concurrency: 8}, "root", "1.0.0")
		var order []string
		for _, node := range result.Nodes {
			order = append(order, node.Ref.Name)
		}
		joined := strings.Join(order, ",")
		if attempt == 0 {
			first = joined
			continue
		}
		if joined != first {
			t.Fatalf("порядок узлов не стабилен:\n%s\n%s", first, joined)
		}
	}
}

// Кэш версий — не оптимизация ради оптимизации: без него дерево из сотни
// узлов дало бы сотни повторных запросов к реестру.
func TestVersionsAreCached(t *testing.T) {
	packages := map[string]map[string][]string{
		"root":   {"1.0.0": {"a", "b", "c"}},
		"a":      {"1.0.0": {"common"}},
		"b":      {"1.0.0": {"common"}},
		"c":      {"1.0.0": {"common"}},
		"common": {"1.0.0": nil},
	}
	fake := &fakePyPI{packages: packages}
	result := walk(t, fake, resolve.Options{MaxDepth: 3, MaxNodes: 50, Concurrency: 4}, "root", "1.0.0")
	if result.CacheHits == 0 {
		t.Fatal("common требуется тремя пакетами — кэш версий обязан сработать")
	}
	if result.Requests >= int(fake.requests)+1 && result.Requests == 0 {
		t.Fatalf("счётчик запросов не заполняется: %d", result.Requests)
	}
}

func TestUnsupportedManagerIsNamed(t *testing.T) {
	fake := &fakePyPI{packages: map[string]map[string][]string{}}
	reg := registry.New(registry.Config{HTTP: fake})
	r := resolve.New(reg, resolve.DefaultOptions(), nil)
	if !r.Supports("pypi") {
		t.Error("pypi обязан поддерживаться")
	}
	if r.Supports("maven") {
		t.Error("нереализованный менеджер не может поддерживаться")
	}
	if _, err := r.Walk(context.Background(), "maven", nil); err == nil {
		t.Error("для неизвестного менеджера ожидалась ошибка")
	}
}
