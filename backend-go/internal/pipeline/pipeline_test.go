package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/pipeline"
	"moderation/internal/policy"
	"moderation/internal/reports"
	"moderation/internal/scanners"
	"moderation/internal/storage"
)

// --------------------------------------------------------------------- шаги 0–3

func TestDbCheckTerminalBranches(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	cases := []struct{ initial, wantStatus, wantResult string }{
		{"approved", "approved", "pass"},
		{"blacklisted", "blacklisted", "fail"},
		{"revoked", "revoked", "fail"},
	}
	for _, c := range cases {
		t.Run(c.initial, func(t *testing.T) {
			e := newEnv(t, r)
			pkg, ver, item := setup(t, r, "requests", "2.31.0-"+c.initial)
			if err := r.UpdatePackageVersionStatus(ctx, ver.ID, c.initial, nil); err != nil {
				t.Fatalf("подготовка версии: %v", err)
			}
			ver.Status = c.initial

			res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.ItemStatus != c.wantStatus {
				t.Fatalf("ItemStatus = %q, ожидался %q", res.ItemStatus, c.wantStatus)
			}
			steps := stepsByCode(t, r, item.ID)
			if len(steps) != 1 || steps["db_check"].Result != c.wantResult {
				t.Fatalf("ожидался единственный db_check/%s, получено %+v", c.wantResult, steps)
			}
		})
	}
}

func TestBlacklistStopsBeforeDownload(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "left-pad", "1.3.0")
	pc := e.context(pkg, ver, item)
	// Правило по glob: имя пакета namespace'ится именем теста (см. setup).
	pc.BL = &policy.Blacklist{Rules: []policy.Rule{
		{Name: "left-pad*", Versions: "*", Reason: "исторически проблемный пакет"},
	}}

	res, err := pipeline.Run(ctx, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "blacklisted" {
		t.Fatalf("ItemStatus = %q", res.ItemStatus)
	}
	// Запрещённый пакет наружу не скачивается — это весь смысл шага.
	if e.fetcher.calls != 0 {
		t.Errorf("выполнено скачиваний: %d — запрещённый пакет ушёл наружу", e.fetcher.calls)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["blacklist"].Result != "fail" || len(steps) != 2 {
		t.Errorf("шаги = %+v", steps)
	}
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "blacklisted" {
		t.Errorf("статус версии = %q", got.Status)
	}
}

func TestQuarantineHoldsFreshVersion(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "fresh-pkg", "1.0.0")
	published := e.now.AddDate(0, 0, -2)
	ver.PublishedAt = &published

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "quarantined" {
		t.Fatalf("ItemStatus = %q, ожидался quarantined", res.ItemStatus)
	}
	if e.fetcher.calls != 0 {
		t.Error("пакет в карантине скачан")
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["quarantine"].Result != "warn" {
		t.Errorf("quarantine = %q", steps["quarantine"].Result)
	}
	// Карантин — непогашенная блокировка.
	if !pipeline.IsOpenResult("quarantine", steps["quarantine"].Result) {
		t.Error("карантин не считается непогашенной блокировкой")
	}
}

// TestLicenseDoesNotStopPipeline — центральная механика сервиса: шаг лицензии,
// не пройденный автоматически, конвейер НЕ останавливает. Пакет уходит дальше
// на скачивание и сканирование, чтобы DevSecOps увидел его в своей очереди
// сразу, а не после решения юриста.
func TestLicenseDoesNotStopPipeline(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)
	// Справочник не разрешает ничего — лицензия уходит юристу.
	pc.Lic = licensePolicy()

	res, err := pipeline.Run(ctx, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	steps := stepsByCode(t, r, item.ID)
	if steps["license"].Result != "warn" {
		t.Fatalf("license = %q, ожидался warn", steps["license"].Result)
	}
	// Конвейер пошёл дальше: скачивание и сканирование выполнены.
	for _, code := range []string{"download", "vuln_scan", "banner_scan", "sast_scan"} {
		if _, ok := steps[code]; !ok {
			t.Errorf("шаг %s не выполнен — конвейер остановился на лицензии", code)
		}
	}
	if e.fetcher.calls != 1 {
		t.Errorf("скачиваний: %d, ожидалось 1", e.fetcher.calls)
	}
	// Публикация при этом НЕ состоялась.
	if steps["publish"].Result != "warn" {
		t.Errorf("publish = %q, ожидался warn (публикация отложена)", steps["publish"].Result)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован при непогашенной блокировке лицензии")
	}
	if res.ItemStatus != "awaiting_legal" {
		t.Errorf("ItemStatus = %q, ожидался awaiting_legal", res.ItemStatus)
	}
}

// --------------------------------------------------------------------- золотой путь

func TestGoldenPathPublishes(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v, ожидался approved/terminal", res)
	}

	steps := stepsByCode(t, r, item.ID)
	if len(steps) != 9 {
		t.Fatalf("выполнено шагов: %d, ожидалось 9: %+v", len(steps), steps)
	}
	for code, step := range steps {
		if step.Result != "pass" {
			t.Errorf("шаг %s = %q, ожидался pass", code, step.Result)
		}
	}
	if len(e.artifacts.published) != 1 {
		t.Errorf("опубликовано артефактов: %d", len(e.artifacts.published))
	}
	// Карантинная зона временная: объект удаляется сразу после публикации.
	objects, err := e.storage.List(ctx, "pypi/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Errorf("объект остался во временном хранилище после публикации: %+v", objects)
	}
	// А отчёты — остаются.
	if got, _ := e.storage.List(ctx, "reports/"); len(got) != 4 {
		t.Errorf("файлов отчётов: %d, ожидалось 4 (2 шага × json+html)", len(got))
	}

	artifact, err := r.CurrentArtifact(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Status != "published" || artifact.NexusURL == nil {
		t.Errorf("артефакт = %+v", artifact)
	}
	if artifact.S3DeletedAt == nil {
		t.Error("время удаления объекта из карантинной зоны не проставлено")
	}
}

// --------------------------------------------------------------------- шаг 4

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// Реестр заявляет sha256, который не совпадёт с содержимым.
	e.registry = registryWithChecksum(t, "sha256",
		"0000000000000000000000000000000000000000000000000000000000000000")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "failed" {
		t.Fatalf("ItemStatus = %q, ожидался failed", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["download"].Result != "fail" {
		t.Fatalf("download = %q", steps["download"].Result)
	}
	if !strings.Contains(*steps["download"].Message, "Контрольная сумма") {
		t.Errorf("сообщение = %q", *steps["download"].Message)
	}
	// Артефакт с несовпавшей суммой не должен попасть в хранилище.
	if objects, _ := e.storage.List(ctx, "pypi/"); len(objects) != 0 {
		t.Errorf("артефакт с неверной суммой записан в хранилище: %+v", objects)
	}
}

// TestDownloadUnknownChecksumAlgoIsNotSilentPass — алгоритм, который мы не
// умеем считать (go h1), не должен молча читаться как «сумма совпала».
func TestDownloadUnknownChecksumAlgoIsNotSilentPass(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.registry = registryWithChecksum(t, "h1", "h1:abcdef==")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["download"].Result != "pass" {
		t.Fatalf("download = %q, неподдержанный алгоритм не должен валить шаг", steps["download"].Result)
	}
	if !strings.Contains(*steps["download"].Message, "не сверялась") {
		t.Errorf("сообщение = %q — не сказано, что сумма не сверялась", *steps["download"].Message)
	}
}

// --------------------------------------------------------------------- шаг 5

func TestVulnAboveThresholdGoesToSecurity(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	e.index.Records = []osv.Record{criticalRecord(t, pkg.Name)}

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, ожидался awaiting_security", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["vuln_scan"].Result != "fail" {
		t.Fatalf("vuln_scan = %q", steps["vuln_scan"].Result)
	}
	// fail у vuln_scan — это непогашенная блокировка, а не отказ: решение
	// принимает DevSecOps.
	if !pipeline.IsOpenResult("vuln_scan", "fail") {
		t.Error("fail у vuln_scan не считается непогашенной блокировкой")
	}
	// Отклонённый на шаге 5 артефакт вычищается из карантинной зоны сразу.
	if objects, _ := e.storage.List(ctx, "pypi/"); len(objects) != 0 {
		t.Errorf("артефакт не вычищен после отклонения: %+v", objects)
	}
	// Уязвимость сохранена.
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxVulnScore == nil || *got.MaxVulnScore < 90 {
		t.Errorf("MaxVulnScore = %v", got.MaxVulnScore)
	}
}

// TestStaleIndexDoesNotAutoApprove — молча одобрять на устаревших данных нельзя.
func TestStaleIndexDoesNotAutoApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	old := e.now.AddDate(0, 0, -30)
	e.index.Version = &osv.IndexVersion{Version: "stale-1", Source: "static", PublishedAt: &old}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, устаревшая база должна звать DevSecOps", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["vuln_scan"].Result != "warn" {
		t.Fatalf("vuln_scan = %q", steps["vuln_scan"].Result)
	}
	if !strings.Contains(*steps["vuln_scan"].Message, "устарела") {
		t.Errorf("сообщение = %q", *steps["vuln_scan"].Message)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован по устаревшей базе уязвимостей")
	}
}

// TestMissingSnapshotDoesNotAutoApprove — отсутствующий снапшот тоже не «чисто».
func TestMissingSnapshotDoesNotAutoApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.index.Version = nil // снапшот ни разу не загружался
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — пакет проскочил бы без базы уязвимостей", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован без загруженной базы уязвимостей")
	}
}

// --------------------------------------------------------------------- шаги 6–7

// TestUnavailableScannerIsNotClean — самое важное свойство шагов сканирования.
func TestUnavailableScannerIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.banner.outcome = scanners.Outcome{Available: false, Detail: "правила не найдены: /config/rules.yar"}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — недоступный сканер прочитан как «чисто»", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["banner_scan"].Result != "warn" {
		t.Fatalf("banner_scan = %q", steps["banner_scan"].Result)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован при неотработавшем сканере")
	}
	// И отчёт об этом есть, с явным состоянием unavailable.
	report, err := r.GetScanReport(ctx, item.ID, "banner_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "unavailable" {
		t.Fatalf("отчёт = %+v, ожидалось состояние unavailable", report)
	}
	// И никаких счётчиков находок: ноль по невыполненной проверке — не
	// измерение, а его отсутствие. В карточке «найдено: 0» читалось ровно
	// наоборот — «проверили, чисто».
	if _, ok := steps["banner_scan"].Details["findings_total"]; ok {
		t.Errorf("детали шага = %v — счётчик находок по невыполненной проверке",
			steps["banner_scan"].Details)
	}
}

// TestSastNeverBlocksPublication — SAST информационный: находки выше порога
// сохраняются и попадают в отчёт, но публикацию не задерживают и в очередь
// DevSecOps пакет из-за них не уходит.
//
// Именно этим SAST отличается от баннеров: срабатывание semgrep на
// eval/exec в библиотеке — обычное дело, и блокировка означала бы ручное
// подтверждение каждого второго пакета.
func TestSastNeverBlocksPublication(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "файлов: 30",
		Findings: []scanners.Finding{
			{Scanner: "semgrep", RuleID: "exec-detected", Severity: "critical",
				Message: "exec", File: "pkg/gen.py", Line: 53},
			{Scanner: "semgrep", RuleID: "eval-detected", Severity: "high",
				Message: "eval", File: "pkg/recompiler.py", Line: 80},
		}}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v — находки SAST задержали публикацию", res)
	}
	if len(e.artifacts.published) != 1 {
		t.Fatal("пакет не опубликован — SAST не должен этому мешать")
	}

	steps := stepsByCode(t, r, item.ID)
	// info, а не pass: «пройден» рядом с двумя находками читается как «чисто».
	if steps["sast_scan"].Result != "info" {
		t.Errorf("sast_scan = %q, ожидался info", steps["sast_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sast_scan"]), "найдено срабатываний — 2") {
		t.Errorf("сообщение шага = %q — число находок должно быть в карточке",
			stepMessage(steps["sast_scan"]))
	}
	// Шаг не считается непогашенным согласованием ни при каком результате.
	if pipeline.IsOpenResult("sast_scan", steps["sast_scan"].Result) {
		t.Error("результат SAST считается непогашенной блокировкой")
	}
	// Находки и отчёт при этом на месте — они и есть смысл шага.
	report, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.FindingsTotal != 2 {
		t.Fatalf("отчёт = %+v, ожидалось 2 находки", report)
	}
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Errorf("находок сохранено %d, ожидалось 2", len(findings))
	}
}

// TestSastUnavailableIsNotSilentPass — неотработавший SAST публикацию не
// держит (шаг информационный), но и «чисто» не значит: pass здесь означал бы
// «проверено, находок нет», а проверки не было.
func TestSastUnavailableIsNotSilentPass(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sast.outcome = scanners.Outcome{Available: false, Detail: "сканер не установлен: semgrep"}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v — информационный шаг задержал публикацию", res)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sast_scan"].Result != "info" {
		t.Errorf("sast_scan = %q, ожидался info", steps["sast_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sast_scan"]), "НЕ выполнена") {
		t.Errorf("сообщение шага = %q — в карточке должно быть видно, что проверки не было",
			stepMessage(steps["sast_scan"]))
	}
	// Счётчика находок по невыполненной проверке быть не должно: ноль здесь
	// читается как «проверили, чисто».
	if _, ok := steps["sast_scan"].Details["findings_total"]; ok {
		t.Errorf("детали шага = %v — счётчик находок по невыполненной проверке",
			steps["sast_scan"].Details)
	}
	report, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "unavailable" {
		t.Fatalf("отчёт = %+v, ожидалось состояние unavailable", report)
	}
}

// TestScannerErrorDoesNotBreakPipeline — падение сканера это «проверка не
// выполнена», а не техническая авария заявки.
func TestScannerErrorDoesNotBreakPipeline(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.banner.err = errors.New("сегфолт в правилах")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("падение сканера уронило конвейер: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Errorf("ItemStatus = %q", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["banner_scan"].Result != "warn" {
		t.Errorf("banner_scan = %q", steps["banner_scan"].Result)
	}
}

// TestBannerFindingHasNoThreshold — баннер находка сама по себе: любое
// совпадение правила уходит DevSecOps, даже с низкой серьёзностью.
func TestBannerFindingHasNoThreshold(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.banner.outcome = scanners.Outcome{Available: true, Detail: "правил сработало: 1",
		Findings: []scanners.Finding{{
			Scanner: "yara", RuleID: "political_banner", Severity: "info",
			Message: "Совпадение правила", File: "pkg/main.py", Line: 1,
		}}}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — находка баннера ниже порога была пропущена", res.ItemStatus)
	}
	report, err := r.GetScanReport(ctx, item.ID, "banner_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report.FindingsBlocking != 1 {
		t.Errorf("FindingsBlocking = %d, у баннеров блокирует любое совпадение", report.FindingsBlocking)
	}
}

// TestSastBelowThresholdPasses — у SAST порог есть, и находка ниже него
// публикацию не блокирует, но в отчёте остаётся.
func TestSastBelowThresholdPasses(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "файлов: 1",
		Findings: []scanners.Finding{{
			Scanner: "semgrep", RuleID: "no-print", Severity: "low",
			Message: "print в библиотеке", File: "pkg/main.py", Line: 1,
		}}}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v, находка ниже порога не должна блокировать", res)
	}
	report, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "clean" || report.FindingsTotal != 1 || report.FindingsBlocking != 0 {
		t.Errorf("отчёт = %+v", report)
	}
	// Находка при этом сохранена и видна в карточке.
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "no-print" {
		t.Errorf("находки = %+v", findings)
	}
}

// TestDisabledScanIsExplicit — выключенный шаг отдаёт pass с явной пометкой, а
// не молча пропускается, и отчёта не пишет: прогона не было.
func TestDisabledScanIsExplicit(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.config.SASTEnabled = false
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sast_scan"].Result != "pass" {
		t.Fatalf("sast_scan = %q", steps["sast_scan"].Result)
	}
	if !strings.Contains(*steps["sast_scan"].Message, "SAST_ENABLED") {
		t.Errorf("сообщение = %q — не названа настройка, которой шаг выключен", stepMessage(steps["sast_scan"]))
	}
	if e.sast.calls != 0 {
		t.Error("выключенный сканер всё-таки вызван")
	}
	report, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report != nil {
		t.Error("для выключенного шага записан отчёт — прогона не было")
	}
}

// TestReportFilesAreStored — отчёты попадают в хранилище обоими форматами и
// содержат то, что нужно для разбора.
func TestReportFilesAreStored(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "файлов: 1",
		Findings: []scanners.Finding{{
			Scanner: "semgrep", RuleID: "python.dangerous-exec", Severity: "high",
			Message: "Вызов exec с внешними данными", File: "pkg/main.py", Line: 3,
			Matched: "exec(code)",
		}}}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	row, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatal("строка отчёта не записана")
	}
	if row.State != "findings" || row.FindingsBlocking != 1 {
		t.Errorf("сводка отчёта = %+v", row)
	}
	if row.JSONKey != storage.ReportKey(item.ID, "sast_scan", "json") {
		t.Errorf("JSONKey = %q", row.JSONKey)
	}

	jsonBody, err := e.storage.Get(ctx, row.JSONKey)
	if err != nil {
		t.Fatalf("JSON-отчёт не найден в хранилище: %v", err)
	}
	var report reports.Report
	if err := json.Unmarshal(jsonBody, &report); err != nil {
		t.Fatalf("JSON-отчёт не разбирается: %v", err)
	}
	if report.Package.Name != pkg.Name || report.Summary.Blocking != 1 {
		t.Errorf("содержимое отчёта = %+v", report.Summary)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "python.dangerous-exec" {
		t.Errorf("находки в отчёте = %+v", report.Findings)
	}
	// sha256 артефакта в отчёте — по нему отчёт связывается с конкретными байтами.
	if report.Package.SHA256 == "" {
		t.Error("sha256 артефакта отсутствует в отчёте")
	}

	htmlBody, err := e.storage.Get(ctx, row.HTMLKey)
	if err != nil {
		t.Fatalf("HTML-отчёт не найден: %v", err)
	}
	if !strings.Contains(string(htmlBody), "python.dangerous-exec") {
		t.Error("находка отсутствует в HTML-отчёте")
	}
}

// TestReportSurvivesRerun — повторный прогон обновляет отчёт, а не плодит строки.
func TestReportSurvivesRerun(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)

	if _, err := pipeline.Run(ctx, pc, ""); err != nil {
		t.Fatalf("первый прогон: %v", err)
	}
	first, _ := r.GetScanReport(ctx, item.ID, "banner_scan")

	// Второй прогон — сканер теперь что-то нашёл.
	e.banner.outcome = scanners.Outcome{Available: true, Detail: "правил сработало: 1",
		Findings: []scanners.Finding{{Scanner: "yara", RuleID: "banner", Severity: "high",
			Message: "совпадение", File: "pkg/main.py", Line: 1}}}
	pc2 := e.context(pkg, ver, item)
	if _, err := pipeline.Run(ctx, pc2, "download"); err != nil {
		t.Fatalf("второй прогон: %v", err)
	}

	second, err := r.GetScanReport(ctx, item.ID, "banner_scan")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Errorf("создан новый отчёт вместо обновления: %d -> %d", first.ID, second.ID)
	}
	if second.State != "findings" {
		t.Errorf("отчёт не обновился: %+v", second)
	}
	all, err := r.ListScanReports(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("отчётов: %d, ожидалось 2 (по одному на шаг сканирования)", len(all))
	}
}

// --------------------------------------------------------------------- решение DevSecOps

// TestSecurityOverrideUnblocksAllScanSteps — без этого возобновлённый после
// одобрения конвейер снова упёрся бы в тот же вердикт и вернул пакет в
// очередь: решение DevSecOps не имело бы эффекта.
func TestSecurityOverrideUnblocksAllScanSteps(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// Всё сразу против пакета: уязвимость выше порога, баннер и находка SAST
	// (последняя публикацию не блокирует, но в карточке должна остаться).
	e.banner.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "yara", RuleID: "banner", Severity: "high",
			Message: "совпадение", File: "pkg/main.py", Line: 1}}}
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "semgrep", RuleID: "exec", Severity: "high",
			Message: "exec", File: "pkg/main.py", Line: 1}}}

	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	e.index.Records = []osv.Record{criticalRecord(t, pkg.Name)}

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("первый прогон: %v", err)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("пакет опубликован при открытых блокировках")
	}

	// DevSecOps разрешает публикацию.
	user, err := r.GetOrCreateUser(ctx, "sec.petrov", "Пётр Петров")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetSecurityOverride(ctx, ver.ID, user.ID, "Проверено вручную, ложные срабатывания"); err != nil {
		t.Fatalf("SetSecurityOverride: %v", err)
	}
	fresh, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Конвейер возобновляется с шага скачивания — как это делает decide_security.
	pc := e.context(pkg, fresh, item)
	res, err := pipeline.Run(ctx, pc, "download")
	if err != nil {
		t.Fatalf("возобновление: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v, решение DevSecOps не сработало", res)
	}
	if len(e.artifacts.published) != 1 {
		t.Error("пакет не опубликован после разрешения DevSecOps")
	}

	steps := stepsByCode(t, r, item.ID)
	for _, code := range pipeline.SecurityBlockers {
		if steps[code].Result != "pass" {
			t.Errorf("шаг %s = %q, решение DevSecOps должно закрывать блокировки "+
				"по содержимому сразу", code, steps[code].Result)
		}
	}
	// SAST решение DevSecOps не касается: он информационный, и его находки
	// остаются записью о прогоне, а не «разрешёнными вручную».
	if steps["sast_scan"].Result != "info" {
		t.Errorf("sast_scan = %q, ожидался info", steps["sast_scan"].Result)
	}
	// Имя принявшего решение попало в отчёт.
	report, err := r.GetScanReport(ctx, item.ID, "sast_scan")
	if err != nil {
		t.Fatal(err)
	}
	jsonBody, err := e.storage.Get(ctx, report.JSONKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonBody), "Пётр Петров") {
		t.Error("решение DevSecOps не отражено в отчёте — находки выглядели бы проигнорированными")
	}
}

// --------------------------------------------------------------------- шаг 8

func TestPublishBlockedByOpenLicense(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)
	pc.Lic = licensePolicy()

	if _, err := pipeline.Run(ctx, pc, ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	msg := *steps["publish"].Message
	if !strings.Contains(msg, "Публикация отложена") || !strings.Contains(msg, "юристов") {
		t.Errorf("сообщение publish = %q", msg)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован при открытой блокировке лицензии")
	}
}

func TestDryRunDoesNotApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.artifacts.dryRun = true
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Публикации не было — пакет не одобрен, иначе команда установки вела бы
	// в никуда.
	if res.ItemStatus != "dry_run" {
		t.Errorf("ItemStatus = %q, ожидался dry_run", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("в режиме dry-run что-то опубликовано")
	}
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == "approved" {
		t.Error("версия помечена одобренной без публикации")
	}
}

func TestPublishFailureIsReported(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.artifacts.publishErr = errors.New("Deploy denied: repository is moderated")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "failed" {
		t.Fatalf("ItemStatus = %q", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	// Ровно этот ответ отличает «прямой PUT запрещён» от «нет прав» — открытый
	// вопрос про боевой Artifactory (docs/ci-parity-gaps.md).
	if !strings.Contains(*steps["publish"].Message, "repository is moderated") {
		t.Errorf("сообщение = %q — ответ артефактори потерян", *steps["publish"].Message)
	}
}

// --------------------------------------------------------------------- возобновление

func TestResumeFromStepSkipsEarlier(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), "download"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	for _, code := range []string{"db_check", "blacklist", "quarantine", "license"} {
		if _, ok := steps[code]; ok {
			t.Errorf("шаг %s выполнен, хотя возобновление было с download", code)
		}
	}
	if len(steps) != 5 {
		t.Errorf("шагов: %d, ожидалось 5 (download..publish)", len(steps))
	}
}

func TestUnknownResumeStep(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	if _, err := pipeline.Run(context.Background(), e.context(pkg, ver, item), "нет-такого"); err == nil {
		t.Error("неизвестный код шага принят")
	}
}

// --------------------------------------------------------------------- вспомогательное

func criticalRecord(t *testing.T, name string) osv.Record {
	t.Helper()
	var rec osv.Record
	body := `{
	  "id": "GHSA-test-crit",
	  "summary": "Удалённое выполнение кода",
	  "affected": [{"package": {"ecosystem": "PyPI", "name": "` + name + `"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
	  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
	}`
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

var _ = time.Now

// stepMessage — сообщение шага. Поле nullable: у шага, который не выполнялся,
// сообщения нет.
func stepMessage(step domain.PipelineStep) string {
	if step.Message == nil {
		return ""
	}
	return *step.Message
}
