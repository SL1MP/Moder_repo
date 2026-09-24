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
	"moderation/internal/registry"
	"moderation/internal/reports"
	"moderation/internal/sandbox"
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

// TestQuarantineMetadataFailureCanBeReleasedManually — если реестр не дал
// дату публикации, интерфейс предлагает DevSecOps снять карантин вручную.
// Для этого статус обязан быть quarantined: ReleaseQuarantine не принимает
// awaiting_security, и прежнее значение делало кнопку гарантированно битой.
func TestQuarantineMetadataFailureCanBeReleasedManually(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.registry = registry.New(registry.Config{
		PyPIURL: "https://pypi.test",
		HTTP:    &fakeRegistryHTTP{responses: map[string]string{}},
	})
	pkg, ver, item := setup(t, r, "metadata-unavailable", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "quarantined" {
		t.Fatalf("ItemStatus = %q, кнопка снятия карантина требует quarantined", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["quarantine"].Result != "warn" {
		t.Errorf("quarantine = %q, ожидался warn", steps["quarantine"].Result)
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
	for _, code := range []string{"download", "vuln_scan", "sandbox_scan"} {
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
	if len(steps) != len(domain.StepCodes) {
		t.Fatalf("выполнено шагов: %d, ожидалось %d: %+v",
			len(steps), len(domain.StepCodes), steps)
	}
	for code, step := range steps {
		if step.Result != "pass" {
			t.Errorf("шаг %s = %q, ожидался pass", code, step.Result)
		}
	}
	if len(e.artifacts.published) != 1 {
		t.Errorf("опубликовано артефактов: %d", len(e.artifacts.published))
	}
	// Основной путь публикации — перенос файла внутри артефактори, без
	// прогона байтов через сервис. Запасной (скачать и выгрузить) существует
	// для Nexus, и проверять по нему золотой путь значило бы не заметить, что
	// перенос сломался.
	if mode := steps["publish"].Details["publish_mode"]; mode != "move" {
		t.Errorf("способ публикации = %v, ожидался перенос внутри артефактори", mode)
	}
	// Промежуточная зона временная: файл уходит из неё сразу после публикации.
	objects, err := e.storage.List(ctx, "pypi/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Errorf("файл остался в промежуточной зоне после публикации: %+v", objects)
	}
	// А отчёты — остаются, и в своём хранилище.
	if got, _ := e.reports.List(ctx, "reports/"); len(got) != 2 {
		t.Errorf("файлов отчётов: %d, ожидалось 2 (один шаг сканирования × json+html)", len(got))
	}

	artifact, err := r.CurrentArtifact(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Status != "published" || artifact.NexusURL == nil {
		t.Errorf("артефакт = %+v", artifact)
	}
	if artifact.StagingClearedAt == nil {
		t.Error("время очистки промежуточной зоны не проставлено")
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

// --------------------------------------------------------------------- шаг 6: песочница

// TestSandboxUnavailableIsNotClean — песочница не ответила. Это «проверка не
// выполнена», а не «чисто»: публикация останавливается, решение принимает
// DevSecOps. Тот же принцип, что у устаревшего снапшота OSV.
func TestSandboxUnavailableIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.err = errors.New("запрос к песочнице https://sandbox.test: connection refused")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — неответившая песочница прочитана как «чисто»", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "warn" {
		t.Fatalf("sandbox_scan = %q, ожидался warn", steps["sandbox_scan"].Result)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован при неотработавшей песочнице")
	}
	// Отчёт есть, с явным состоянием unavailable: «проверки не было» обязано
	// быть видно, а не отсутствовать файлом.
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "unavailable" {
		t.Fatalf("отчёт = %+v, ожидалось состояние unavailable", report)
	}
	// И никаких счётчиков находок: ноль по невыполненной проверке — не
	// измерение, а его отсутствие. В карточке «найдено: 0» читалось ровно
	// наоборот — «проверили, чисто».
	if _, ok := steps["sandbox_scan"].Details["findings_total"]; ok {
		t.Errorf("детали шага = %v — счётчик находок по невыполненной проверке",
			steps["sandbox_scan"].Details)
	}
}

// TestSandboxNotConfiguredIsNotClean — адрес песочницы не задан. Отличается от
// предыдущего тем, что до сети дело не дошло вовсе, а вести себя обязано так
// же: выключать проверку молча, потому что её забыли настроить, нельзя.
func TestSandboxNotConfiguredIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.available = false
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — ненастроенная песочница прочитана как «чисто»", res.ItemStatus)
	}
	if e.sandbox.calls != 0 {
		t.Error("ненастроенная песочница всё-таки опрошена")
	}
	steps := stepsByCode(t, r, item.ID)
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SANDBOX_URL") {
		t.Errorf("сообщение = %q — не названа настройка, которой задаётся адрес",
			stepMessage(steps["sandbox_scan"]))
	}
}

// TestSandboxDangerousBlocksPublication — вердикт DANGEROUS. Публикация
// останавливается, пакет уходит DevSecOps, находки видны в карточке и в
// отчёте, ссылка на задачу в песочнице — в деталях шага.
func TestSandboxDangerousBlocksPublication(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-42",
		Detections: []sandbox.Detection{
			{Name: "Trojan.Generic", Type: "malware", Severity: "critical",
				Details: "сетевое соединение с C2"},
			{Name: "Persistence.Cron"},
		},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, ожидался awaiting_security", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("пакет с вердиктом DANGEROUS опубликован")
	}

	steps := stepsByCode(t, r, item.ID)
	step := steps["sandbox_scan"]
	if step.Result != "fail" {
		t.Errorf("sandbox_scan = %q, ожидался fail", step.Result)
	}
	if step.Details["verdict"] != sandbox.VerdictDangerous {
		t.Errorf("вердикт в деталях = %v", step.Details["verdict"])
	}
	// Ссылка на задачу — то, по чему DevSecOps открывает отчёт песочницы.
	// Без неё «посмотрите в песочнице» означает «найдите сами».
	if step.Details["task_url"] != "https://sandbox.test/tasks/scan-42" {
		t.Errorf("ссылка на задачу = %v", step.Details["task_url"])
	}

	// Находки сохранены и видны в карточке.
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("находок сохранено: %d, ожидалось 2 (%+v)", len(findings), findings)
	}
	// Серьёзность, которую песочница не прислала, не проваливается в info:
	// находка динамического анализа — это то, что образец сделал при запуске.
	bySeverity := map[string]string{}
	for _, f := range findings {
		bySeverity[f.RuleID] = f.Severity
	}
	if bySeverity["Persistence.Cron"] != "high" {
		t.Errorf("серьёзность без значения = %q, ожидалось high", bySeverity["Persistence.Cron"])
	}
	if bySeverity["Trojan.Generic"] != "critical" {
		t.Errorf("серьёзность из ответа песочницы потеряна: %q", bySeverity["Trojan.Generic"])
	}

	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "findings" || report.FindingsTotal != 2 {
		t.Errorf("отчёт = %+v", report)
	}
}

// TestSandboxUnwantedDoesNotBlock — вердикт UNWANTED информационный: пометка в
// карточке и в отчёте есть, публикацию он не держит (решение пользователя).
//
// Это и отличает его от DANGEROUS: «нежелательное» — не «вредоносное», и
// звать DevSecOps на каждый пакет с рекламным SDK внутри незачем.
func TestSandboxUnwantedDoesNotBlock(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictUnwanted, ScanID: "scan-7",
		Detections: []sandbox.Detection{{Name: "Adware.Tracker", Severity: "low"}},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v — вердикт UNWANTED не должен держать публикацию", res)
	}
	if len(e.artifacts.published) != 1 {
		t.Error("пакет не опубликован при вердикте UNWANTED")
	}

	steps := stepsByCode(t, r, item.ID)
	// Именно info, а не pass: «пройден» рядом с находкой читается как «чисто».
	if steps["sandbox_scan"].Result != "info" {
		t.Errorf("sandbox_scan = %q, ожидался info", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "UNWANTED") {
		t.Errorf("сообщение = %q — вердикт не назван", stepMessage(steps["sandbox_scan"]))
	}
	// Находка при этом сохранена: не блокирует — не значит «не показываем».
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Errorf("находки = %+v, ожидалась одна", findings)
	}
}

// TestSandboxUnknownVerdictIsNotClean — песочница вернула значение, которого
// мы не знаем. Пропустить пакет по вердикту, смысла которого мы не понимаем,
// нельзя: это то же «проверка не выполнена».
func TestSandboxUnknownVerdictIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{Verdict: "SUSPICIOUS", ScanID: "scan-9"}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q — незнакомый вердикт прочитан как «чисто»", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "warn" {
		t.Errorf("sandbox_scan = %q, ожидался warn", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SUSPICIOUS") {
		t.Errorf("сообщение = %q — неизвестный вердикт не назван, искать причину негде",
			stepMessage(steps["sandbox_scan"]))
	}
	if len(e.artifacts.published) != 0 {
		t.Error("пакет опубликован при незнакомом вердикте")
	}
}

// TestSandboxReceivesPublishedArtifact — в песочницу уходит ровно тот файл,
// который будет опубликован, а не пересобранный архив.
//
// Проверять другое содержимое, чем то, что поедет разработчикам, значит
// проверять не то: именно это и отличает шаг от CI-версии, которая отправляла
// tar.gz всего проекта, собранный джобой.
func TestSandboxReceivesPublishedArtifact(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if e.sandbox.calls != 1 {
		t.Fatalf("обращений к песочнице: %d, ожидалось 1", e.sandbox.calls)
	}
	artifact, err := r.CurrentArtifact(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.sandbox.lastFile != artifact.Filename {
		t.Errorf("в песочницу ушёл файл %q, а опубликован %q",
			e.sandbox.lastFile, artifact.Filename)
	}
	if artifact.SizeBytes == nil || int64(e.sandbox.lastSize) != *artifact.SizeBytes {
		t.Errorf("в песочницу ушло %d байт, размер артефакта %v",
			e.sandbox.lastSize, artifact.SizeBytes)
	}
}

// TestDisabledScanIsExplicit — выключенный шаг отдаёт pass с явной пометкой, а
// не молча пропускается, и отчёта не пишет: прогона не было.
func TestDisabledScanIsExplicit(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.config.SandboxEnabled = false
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "pass" {
		t.Fatalf("sandbox_scan = %q", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SANDBOX_ENABLED") {
		t.Errorf("сообщение = %q — не названа настройка, которой шаг выключен",
			stepMessage(steps["sandbox_scan"]))
	}
	if e.sandbox.calls != 0 {
		t.Error("выключенная проверка всё-таки обратилась в песочницу")
	}
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report != nil {
		t.Error("для выключенного шага записан отчёт — прогона не было")
	}
}

// TestRetiredStepsDoNotRun — снятые шаги не выполняются.
//
// Настройки и сами шаги оставлены (pipeline.RetiredSteps), и без этой проверки
// включённый по недосмотру BANNER_SCAN_ENABLED вернул бы шаг в строй молча.
func TestRetiredStepsDoNotRun(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// Настройки снятых шагов включены, сканеры готовы что-то найти.
	e.config.BannerScanEnabled = true
	e.config.SASTEnabled = true
	e.banner.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "yara", RuleID: "banner", Severity: "high"}}}
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "semgrep", RuleID: "exec", Severity: "high"}}}

	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("результат = %+v — снятый шаг задержал публикацию", res)
	}
	if e.banner.calls != 0 || e.sast.calls != 0 {
		t.Errorf("снятые сканеры вызваны: banner=%d sast=%d", e.banner.calls, e.sast.calls)
	}
	steps := stepsByCode(t, r, item.ID)
	for _, code := range []string{"banner_scan", "sast_scan"} {
		if _, ok := steps[code]; ok {
			t.Errorf("снятый шаг %s выполнен и записан в историю прогона", code)
		}
	}
}

// TestReportFilesAreStored — отчёты попадают в хранилище обоими форматами и
// содержат то, что нужно для разбора.
func TestReportFilesAreStored(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-1",
		Detections: []sandbox.Detection{{
			Name: "Backdoor.Python.Exec", Type: "malware", Severity: "high",
			Details: "запуск стороннего кода при импорте",
		}},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	row, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatal("строка отчёта не записана")
	}
	if row.State != "findings" || row.FindingsBlocking != 1 {
		t.Errorf("сводка отчёта = %+v", row)
	}
	if row.JSONKey != storage.ReportKey(item.ID, "sandbox_scan", "json") {
		t.Errorf("JSONKey = %q", row.JSONKey)
	}
	// Отчёт лежит в СВОЁМ хранилище, а не рядом с артефактом: артефакт
	// вычищается из промежуточной зоны, отчёт обязан это пережить.
	if row.Bucket == nil || *row.Bucket != e.reports.Bucket() {
		t.Errorf("репозиторий отчёта = %v, ожидался %q", row.Bucket, e.reports.Bucket())
	}

	jsonBody, err := e.reports.Get(ctx, row.JSONKey)
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
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "Backdoor.Python.Exec" {
		t.Errorf("находки в отчёте = %+v", report.Findings)
	}
	// sha256 артефакта в отчёте — по нему отчёт связывается с конкретными байтами.
	if report.Package.SHA256 == "" {
		t.Error("sha256 артефакта отсутствует в отчёте")
	}

	htmlBody, err := e.reports.Get(ctx, row.HTMLKey)
	if err != nil {
		t.Fatalf("HTML-отчёт не найден: %v", err)
	}
	if !strings.Contains(string(htmlBody), "Backdoor.Python.Exec") {
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
	first, _ := r.GetScanReport(ctx, item.ID, "sandbox_scan")

	// Второй прогон — песочница теперь что-то нашла.
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-2",
		Detections: []sandbox.Detection{{Name: "Trojan.Generic", Severity: "critical"}},
	}
	pc2 := e.context(pkg, ver, item)
	if _, err := pipeline.Run(ctx, pc2, "download"); err != nil {
		t.Fatalf("второй прогон: %v", err)
	}

	second, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
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
	if len(all) != 1 {
		t.Errorf("отчётов: %d, ожидался 1 (по одному на шаг сканирования)", len(all))
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
	// Всё сразу против пакета: уязвимость выше порога и вердикт песочницы.
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-13",
		Detections: []sandbox.Detection{{Name: "Trojan.Generic", Severity: "critical"}},
	}

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
	// Имя принявшего решение попало в отчёт: без этого находки песочницы
	// выглядели бы просто проигнорированными.
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	jsonBody, err := e.reports.Get(ctx, report.JSONKey)
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

// TestPublishRefusesCancelledItem — заявку закрыли, пока шёл прогон: пакет не
// публикуется.
//
// Отмена и так снимает пакет с обработки (воркер видит по отметке о жизни,
// что строку «отобрали»), но отметка редкая — раз в 30 секунд, — и публикация
// могла бы проскочить в этот зазор. Публикация — запись во внешний
// артефактори, её потом не отозвать одним UPDATE, поэтому шаг проверяет
// статус заново сам.
func TestPublishRefusesCancelledItem(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	// Отмена приходит после захвата: pc.Item — снимок, в нём её не видно.
	pc := e.context(pkg, ver, item)
	if _, err := r.Pool().Exec(ctx,
		`UPDATE request_item SET status = 'cancelled' WHERE id = $1`, item.ID); err != nil {
		t.Fatal(err)
	}

	res, err := pipeline.Run(ctx, pc, "publish")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("опубликован пакет из закрытой заявки")
	}
	if res.ItemStatus != "cancelled" {
		t.Errorf("ItemStatus = %q, ожидался cancelled", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if !strings.Contains(stepMessage(steps["publish"]), "закрыта автором") {
		t.Errorf("сообщение publish = %q — в карточке должно быть видно, почему не опубликовали",
			stepMessage(steps["publish"]))
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
	// download, vuln_scan, sandbox_scan, publish.
	if want := len(domain.StepCodes) - 4; len(steps) != want {
		t.Errorf("шагов: %d, ожидалось %d (download..publish)", len(steps), want)
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
