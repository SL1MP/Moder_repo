package osv_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"moderation/internal/osv"
)

// --------------------------------------------------------------------- версии

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1}, // числовое сравнение, не лексикографическое
		{"2.0.0", "10.0.0", -1},
		// Пустой prerelease старше любого непустого.
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		// Числовые идентификаторы младше алфавитных.
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0", "1.0.0", 0}, // недостающие компоненты — нули
	}
	for _, c := range cases {
		if got := osv.CompareSemver(c.a, c.b); got != c.want {
			t.Errorf("CompareSemver(%q, %q) = %d, ожидалось %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareGo(t *testing.T) {
	if osv.CompareGo("v1.9.1", "v1.9.0") != 1 {
		t.Error("v1.9.1 должна быть больше v1.9.0")
	}
	// +incompatible не влияет на порядок.
	if osv.CompareGo("v2.0.0+incompatible", "v2.0.0") != 0 {
		t.Error("+incompatible изменил порядок версий")
	}
	if osv.CompareGo("v1.0.0-20240101120000-abcdef123456", "v1.0.0") != -1 {
		t.Error("псевдоверсия должна быть младше релиза")
	}
}

func TestCompareNuGet(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"13.0.3", "13.0.3", 0},
		{"1.0.0.1", "1.0.0", 1}, // четвёртая компонента
		{"1.0", "1.0.0.0", 0},   // недостающие — нули
		{"6.0.0-preview.5", "6.0.0", -1},
		{"6.0.0-preview.5", "6.0.0-preview.10", -1},
	}
	for _, c := range cases {
		if got := osv.CompareNuGet(c.a, c.b); got != c.want {
			t.Errorf("CompareNuGet(%q, %q) = %d, ожидалось %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.31.0", "2.31.0", 0},
		{"1.0", "1.0.0", 0},       // эквивалентны по PEP 440
		{"1.0.0rc1", "1.0.0", -1}, // rc младше релиза
		{"1.0.0a1", "1.0.0b1", -1},
		{"1.0.0", "1.0.0.post1", -1}, // post старше релиза
		{"1.0.0.dev1", "1.0.0", -1},  // dev младше всего
		{"1.10.0", "1.9.0", 1},
	}
	for _, c := range cases {
		if got := osv.ComparePEP440(c.a, c.b); got != c.want {
			t.Errorf("ComparePEP440(%q, %q) = %d, ожидалось %d", c.a, c.b, got, c.want)
		}
	}
}

// --------------------------------------------------------------------- диапазоны

func TestVersionMatchesRange(t *testing.T) {
	r := osv.Range{Type: "ECOSYSTEM", Events: []map[string]string{
		{"introduced": "1.0.0"}, {"fixed": "1.2.0"},
	}}
	cases := map[string]bool{
		"0.9.0": false, // до introduced
		"1.0.0": true,  // граница introduced включительно
		"1.1.9": true,
		"1.2.0": false, // граница fixed исключительно
		"2.0.0": false,
	}
	for version, want := range cases {
		if got := osv.VersionMatchesRange("npm", version, r); got != want {
			t.Errorf("версия %s: попадание = %v, ожидалось %v", version, got, want)
		}
	}
}

func TestVersionMatchesRangeLastAffected(t *testing.T) {
	r := osv.Range{Events: []map[string]string{
		{"introduced": "0"}, {"last_affected": "1.5.0"},
	}}
	// last_affected включительно, в отличие от fixed.
	if !osv.VersionMatchesRange("npm", "1.5.0", r) {
		t.Error("last_affected должна быть включительной границей")
	}
	if osv.VersionMatchesRange("npm", "1.5.1", r) {
		t.Error("версия после last_affected не должна быть затронута")
	}
}

func record(t *testing.T, body string) osv.Record {
	t.Helper()
	var r osv.Record
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("разбор записи: %v", err)
	}
	return r
}

func TestFindingFromRecord(t *testing.T) {
	rec := record(t, `{
	  "id": "GHSA-xxxx-yyyy-zzzz",
	  "summary": "Удалённое выполнение кода",
	  "aliases": ["CVE-2021-0001"],
	  "affected": [{
	    "package": {"ecosystem": "npm", "name": "lodash"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
	  }],
	  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxxx"}]
	}`)

	finding, hit := osv.FindingFromRecord(rec, "npm", "4.17.20")
	if !hit {
		t.Fatal("версия 4.17.20 должна попадать в диапазон")
	}
	if finding.ExternalID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("ExternalID = %q", finding.ExternalID)
	}
	// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — это 9.8 по CVSS v3.1.
	if finding.CVSSScore != 9.8 {
		t.Errorf("CVSSScore = %v, ожидалось 9.8", finding.CVSSScore)
	}
	if finding.Score() != 98 {
		t.Errorf("Score() = %v, ожидалось 98 (шкала 0..100)", finding.Score())
	}
	if len(finding.FixedVersions) != 1 || finding.FixedVersions[0] != "4.17.21" {
		t.Errorf("FixedVersions = %v", finding.FixedVersions)
	}
	if finding.URL != "https://github.com/advisories/GHSA-xxxx" {
		t.Errorf("URL = %q", finding.URL)
	}

	// Исправленная версия не затронута.
	if _, hit := osv.FindingFromRecord(rec, "npm", "4.17.21"); hit {
		t.Error("исправленная версия отмечена как затронутая")
	}
}

// TestFindingIgnoresOtherEcosystems — запись про пакет с тем же именем в
// другой экосистеме не должна блокировать наш пакет.
func TestFindingIgnoresOtherEcosystems(t *testing.T) {
	rec := record(t, `{
	  "id": "OSV-1",
	  "affected": [{
	    "package": {"ecosystem": "PyPI", "name": "lodash"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
	  }]
	}`)
	if _, hit := osv.FindingFromRecord(rec, "npm", "1.0.0"); hit {
		t.Error("запись из чужой экосистемы засчитана")
	}
}

// TestFindingIgnoresGitRanges — git-диапазоны не применимы к версиям реестра;
// без этого любая версия попадала бы в диапазон по коммитам.
func TestFindingIgnoresGitRanges(t *testing.T) {
	rec := record(t, `{
	  "id": "OSV-2",
	  "affected": [{
	    "package": {"ecosystem": "npm", "name": "pkg"},
	    "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]
	  }]
	}`)
	if _, hit := osv.FindingFromRecord(rec, "npm", "1.0.0"); hit {
		t.Error("git-диапазон засчитан для версии реестра")
	}
}

func TestFindingExplicitVersions(t *testing.T) {
	rec := record(t, `{
	  "id": "OSV-3",
	  "affected": [{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.0.0", "1.0.1"]}],
	  "database_specific": {"severity": "HIGH"}
	}`)
	finding, hit := osv.FindingFromRecord(rec, "npm", "1.0.1")
	if !hit {
		t.Fatal("явно перечисленная версия не засчитана")
	}
	// Вектора нет — балл берётся из текстовой оценки.
	if finding.CVSSScore != 7.5 {
		t.Errorf("CVSSScore = %v, ожидалось 7.5 из текстовой оценки HIGH", finding.CVSSScore)
	}
	if _, hit := osv.FindingFromRecord(rec, "npm", "1.0.2"); hit {
		t.Error("версия вне списка засчитана")
	}
}

// --------------------------------------------------------------------- CVSS

func TestCVSSv3Score(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
	}
	for vector, want := range cases {
		got, ok := osv.CVSSv3Score(vector)
		if !ok {
			t.Errorf("вектор %q не разобран", vector)
			continue
		}
		if got != want {
			t.Errorf("CVSSv3Score(%q) = %v, ожидалось %v", vector, got, want)
		}
	}
}

// TestIncompleteCVSSIsNotZero — неполный вектор обязан давать ok=false, а не
// балл 0: ноль означал бы «неопасно».
func TestIncompleteCVSSIsNotZero(t *testing.T) {
	for _, vector := range []string{"", "мусор", "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := osv.CVSSv3Score(vector); ok {
			t.Errorf("неполный вектор %q разобран как валидный", vector)
		}
	}
}

// --------------------------------------------------------------------- снапшот

func writeSnapshot(t *testing.T, records map[string]string, meta string) string {
	t.Helper()
	root := t.TempDir()
	if meta != "" {
		if err := os.WriteFile(filepath.Join(root, "snapshot.json"), []byte(meta), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range records {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSnapshotIndexQuery(t *testing.T) {
	root := writeSnapshot(t, map[string]string{
		"npm/GHSA-1.json": `{
		  "id": "GHSA-1",
		  "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
		    "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
		  "database_specific": {"severity": "CRITICAL"}
		}`,
		"npm/GHSA-2.json": `{
		  "id": "GHSA-2",
		  "affected": [{"package": {"ecosystem": "npm", "name": "express"},
		    "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]
		}`,
	}, `{"version":"2026-09-01","published_at":"2026-09-01T00:00:00Z","record_count":2}`)

	index := osv.NewSnapshotIndex(root)
	ctx := context.Background()

	findings, err := index.Query(ctx, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(findings) != 1 || findings[0].ExternalID != "GHSA-1" {
		t.Fatalf("находки = %+v, ожидалась одна GHSA-1", findings)
	}
	// Запись про другой пакет не должна попасть.
	clean, err := index.Query(ctx, "npm", "lodash", "4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 0 {
		t.Errorf("исправленная версия дала находки: %+v", clean)
	}
}

func TestSnapshotIndexVersionAndStaleness(t *testing.T) {
	published := time.Now().UTC().AddDate(0, 0, -10)
	root := writeSnapshot(t, nil, `{"version":"v1","published_at":"`+
		published.Format(time.RFC3339)+`","record_count":5}`)

	index := osv.NewSnapshotIndex(root)
	ctx := context.Background()

	info, err := index.CurrentVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info == nil || info.Version != "v1" {
		t.Fatalf("CurrentVersion = %+v", info)
	}
	if age := info.AgeDays(time.Now().UTC()); age == nil || *age < 9 || *age > 11 {
		t.Errorf("AgeDays = %v, ожидалось около 10", age)
	}

	stale, err := osv.IsStale(ctx, index, 7, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("снапшот десятидневной давности при лимите 7 дней не признан устаревшим")
	}
	fresh, err := osv.IsStale(ctx, index, 30, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Error("снапшот признан устаревшим при лимите 30 дней")
	}
}

// TestMissingSnapshotIsStale — молча одобрять пакет на данных, которых нет,
// нельзя: отсутствие снапшота обязано считаться устареванием.
func TestMissingSnapshotIsStale(t *testing.T) {
	index := osv.NewSnapshotIndex(filepath.Join(t.TempDir(), "нет-такого"))
	ctx := context.Background()

	info, err := index.CurrentVersion(ctx)
	if err != nil {
		t.Fatalf("CurrentVersion вернул ошибку вместо nil: %v", err)
	}
	if info != nil {
		t.Fatalf("CurrentVersion = %+v, ожидался nil", info)
	}
	stale, err := osv.IsStale(ctx, index, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("отсутствующий снапшот не признан устаревшим — пакет проскочил бы проверку")
	}
	// Запрос по отсутствующей базе — ошибка, а не пустой список.
	if _, err := index.Query(ctx, "npm", "lodash", "1.0.0"); err == nil {
		t.Error("запрос по незагруженной базе вернул пустой список вместо ошибки")
	}
}

func TestSummaryAndMaxScore(t *testing.T) {
	findings := []osv.Finding{
		{ExternalID: "GHSA-1", CVSSScore: 9.8},
		{ExternalID: "CVE-2", CVSSScore: 5.0},
	}
	if got := osv.MaxScore(findings); got != 98 {
		t.Errorf("MaxScore = %v, ожидалось 98", got)
	}
	if got := osv.Summary(findings); got != "GHSA-1 (98), CVE-2 (50)" {
		t.Errorf("Summary = %q", got)
	}
	if osv.Summary(nil) != "" {
		t.Error("Summary для пустого списка не пуста")
	}
}

func TestValidIdentifier(t *testing.T) {
	if osv.ValidIdentifier("../../etc/passwd") {
		t.Error("путь с выходом за пределы каталога принят как имя пакета")
	}
	if !osv.ValidIdentifier("lodash") || !osv.ValidIdentifier("zope.interface") {
		t.Error("нормальное имя пакета отклонено")
	}
}
