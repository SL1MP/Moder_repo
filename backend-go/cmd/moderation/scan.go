package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/pipeline"
	"moderation/internal/policy"
	"moderation/internal/repo"
	"moderation/internal/scanners"
	"moderation/internal/storage"
)

// Команда `moderation scan --item N` — прогон сканеров содержимого по пакету
// УЖЕ СУЩЕСТВУЮЩЕЙ заявки и запись отчётов.
//
// Зачем она есть: REST API создания заявок на Go ещё не перенесён, заявки
// заводит python-версия, а отчёты о сканировании умеет делать только Go. Без
// этой команды отчёты не появились бы ни на одной реальной заявке до конца
// переноса.
//
// Чего команда НАМЕРЕННО не делает: не меняет статус заявки и не пишет строки
// pipeline_step. Ими владеет python-конвейер, и вмешательство второго
// процесса в его состояние дало бы расхождение, которое потом ищут днями.
// Команда пишет ровно своё: файлы отчётов, строку scan_report и находки
// code_finding (их семантика та же, что у сканера python-версии, — «что
// показать в карточке сейчас»).
//
// Артефакт после публикации удаляется из карантинной зоны, поэтому для уже
// одобренного пакета он скачивается заново из реестра — тем же шагом, что и в
// конвейере.

func runScan(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	itemID := fs.Int64("item", 0, "идентификатор пакета заявки (request_item.id)")
	requestID := fs.Int64("request", 0, "номер заявки — просканировать все её пакеты")
	pending := fs.Bool("pending", false,
		"ничего не сканировать, показать, что наблюдатель взял бы в работу")
	why := fs.Int64("why", 0,
		"ничего не сканировать, объяснить, почему по этому пакету нет отчёта")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, on := range []bool{*itemID > 0, *requestID > 0, *pending, *why > 0} {
		if on {
			modes++
		}
	}
	if modes == 0 {
		fmt.Fprintln(os.Stderr, "укажите, что сканировать:")
		fmt.Fprintln(os.Stderr, "  moderation scan --request <номер заявки>   все пакеты заявки")
		fmt.Fprintln(os.Stderr, "  moderation scan --item <id пакета>         один пакет")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "или разберитесь, почему отчёт не появился сам:")
		fmt.Fprintln(os.Stderr, "  moderation scan --pending                  что наблюдатель возьмёт в работу")
		fmt.Fprintln(os.Stderr, "  moderation scan --why <id пакета>          почему по пакету нет отчёта")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Номер заявки виден в адресе её страницы: /requests/42 -> --request 42.")
		fmt.Fprintln(os.Stderr, "Идентификаторы пакетов внутри заявки — в ответе GET /api/v1/requests/{id},")
		fmt.Fprintln(os.Stderr, "поле packages[].id.")
		return 2
	}
	if modes > 1 {
		fmt.Fprintln(os.Stderr, "--item, --request, --pending и --why взаимоисключающие")
		return 2
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		return 1
	}
	defer pool.Close()
	r := repo.New(pool)

	// Диагностика идёт до подключения к хранилищу: она отвечает на вопрос
	// «почему не сработало», и требовать для этого исправного MinIO — значит
	// не отвечать ровно в том случае, когда ответ и нужен.
	if *pending {
		return reportPending(ctx, r, cfg)
	}
	if *why > 0 {
		return explainItem(ctx, r, *why)
	}

	st, err := newStores(cfg, newHTTPClient())
	if err != nil {
		logger.Error("хранилище не настроено — отчёты некуда положить", "error", err)
		return 1
	}

	targets := []int64{*itemID}
	if *requestID > 0 {
		items, err := r.ListItemsByRequest(ctx, *requestID)
		if err != nil {
			logger.Error("заявка не прочитана", "request", *requestID, "error", err)
			return 1
		}
		if len(items) == 0 {
			logger.Error("в заявке нет пакетов — проверьте номер", "request", *requestID)
			return 1
		}
		targets = targets[:0]
		for _, item := range items {
			targets = append(targets, item.ID)
		}
		logger.Info("заявка прочитана", "request", *requestID, "пакетов", len(targets))
	}

	failedAny := false
	for _, target := range targets {
		if err := scanOne(ctx, r, st, cfg, target, logger); err != nil {
			logger.Error("пакет не просканирован", "item", target, "error", err)
			failedAny = true
		}
	}
	if failedAny {
		return 1
	}

	fmt.Printf("\nОтчёты доступны:\n")
	for _, target := range targets {
		for _, code := range domain.ScanReportStepCodes {
			fmt.Printf("  /api/v1/request-items/%d/reports/%s.html\n", target, code)
		}
	}
	return 0
}

// scanOne прогоняет сканеры по одному пакету заявки.
func scanOne(ctx context.Context, r *repo.Repo, st *stores, cfg *config.Config, itemID int64, logger *slog.Logger) error {
	pc, err := buildScanContext(ctx, r, st, cfg)
	if err != nil {
		return err
	}
	if err := loadItem(ctx, r, pc, itemID); err != nil {
		return fmt.Errorf("пакет заявки #%d не найден: %w", itemID, err)
	}

	logger.Info("сканирую пакет",
		"item", itemID, "package", pc.Package.DisplayName, "version", pc.Version.RawVersion)

	// Артефакт мог быть вычищен из карантинной зоны после публикации —
	// скачиваем заново тем же шагом конвейера.
	if err := ensureArtifact(ctx, r, pc, logger); err != nil {
		return fmt.Errorf("артефакт не получен: %w", err)
	}

	for _, step := range []pipeline.Step{pipeline.BannerScanStep, pipeline.SastScanStep} {
		outcome, err := step.Run(ctx, pc)
		if err != nil {
			return fmt.Errorf("шаг %s: %w", step.Code(), err)
		}
		report, err := r.GetScanReport(ctx, pc.Item.ID, step.Code())
		if err != nil {
			return fmt.Errorf("отчёт по шагу %s не прочитан: %w", step.Code(), err)
		}
		if report == nil {
			// Шаг выключен настройкой — прогона не было, отчёта нет.
			logger.Info("отчёт не создан", "step", step.Code(), "причина", outcome.Message)
			continue
		}
		logger.Info("отчёт готов",
			"item", itemID, "step", step.Code(), "состояние", report.State,
			"находок", report.FindingsTotal, "блокирующих", report.FindingsBlocking)
	}
	return nil
}

// buildScanContext собирает конвейерный контекст со всеми зависимостями,
// кроме самого пакета: его подставляет loadItem.
func buildScanContext(_ context.Context, r *repo.Repo, st *stores, cfg *config.Config) (*pipeline.Context, error) {
	httpClient := newHTTPClient()
	reg := newRegistry(cfg, httpClient)

	return &pipeline.Context{
		Config: pipelineConfig(cfg),
		// Политики нужны шагам 1 и 3. Команда их не запускает, но контекст
		// собирается один и тот же — неполный контекст здесь означал бы, что
		// при следующем расширении команды шаги молча получат nil.
		BL:  policy.LoadBlacklist(cfg.BlacklistFile),
		Lic: policy.LoadLicensePolicy(cfg.AllowedLicensesFile),
		Deps: pipeline.Deps{
			Repo: r, Storage: st.Staging, Reports: st.Reports, Registry: reg,
			// Индекс уязвимостей и артефактори нужны шагам 5 и 7. Команде
			// `scan` они не требуются, но контекст собирается один и тот же:
			// неполный контекст уже приводил к падению воркера на шаге, до
			// которого `scan` не доходит.
			Index:     osv.NewSnapshotIndex(cfg.OSVLocalDBPath),
			Artifacts: st.Artifacts,
			Sandbox:   newSandbox(cfg),
			// Сканеры снятых шагов: конвейер их не вызывает, но контекст
			// собирается целиком — см. комментарий к Validate.
			Banner: scanners.YaraScanner{
				Binary: cfg.BannerScanBin, RulesFile: cfg.BannerRulesFile,
				Timeout: cfg.BannerScanTimeout,
			},
			SAST: scanners.SemgrepScanner{
				Binary: cfg.SASTScannerBin, Rules: cfg.SASTRules, Timeout: cfg.SASTTimeout,
			},
			Fetch: httpFetcher{client: httpClient},
		},
	}, nil
}

func loadItem(ctx context.Context, r *repo.Repo, pc *pipeline.Context, itemID int64) error {
	item, err := r.GetRequestItem(ctx, itemID)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("пакета заявки #%d нет в базе", itemID)
	}
	version, err := r.GetPackageVersion(ctx, item.PackageVersionID)
	if err != nil {
		return err
	}
	pkg, err := r.GetPackage(ctx, version.PackageID)
	if err != nil {
		return err
	}
	pc.Item, pc.Version, pc.Package = item, version, pkg
	return nil
}

// ensureArtifact добивается того, чтобы артефакт лежал в карантинной зоне.
func ensureArtifact(ctx context.Context, r *repo.Repo, pc *pipeline.Context, logger *slog.Logger) error {
	artifact, err := r.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return err
	}
	if artifact != nil && artifact.StagingPath != nil && *artifact.StagingPath != "" && artifact.StagingClearedAt == nil {
		if _, err := pc.Deps.Storage.Stat(ctx, *artifact.StagingPath); err == nil {
			return nil
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}

	logger.Info("артефакта нет во временном хранилище — скачиваю заново")
	outcome, err := pipeline.DownloadStep{}.Run(ctx, pc)
	if err != nil {
		return err
	}
	if outcome.Result != "pass" {
		return fmt.Errorf("шаг скачивания не прошёл: %s", outcome.Message)
	}
	return nil
}

// httpFetcher — скачивание артефакта. Лимит проверяется и по заголовку, и по
// фактически прочитанному: заголовку внешнего сервера верить нельзя.
type httpFetcher struct{ client *http.Client }

func (f httpFetcher) Fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("реестр ответил %d при скачивании артефакта", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("размер артефакта %d байт превышает лимит %d", resp.ContentLength, limit)
	}
	data, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("размер артефакта превышает лимит %d байт", limit)
	}
	return data, nil
}

// reportPending — что наблюдатель взял бы в работу прямо сейчас. Та же
// выборка, которой он пользуется, а не похожая: смысл диагностики в том,
// чтобы показать реальное поведение, а не его пересказ.
func reportPending(ctx context.Context, r *repo.Repo, cfg *config.Config) int {
	if !cfg.ScanWatcherEnabled {
		fmt.Println("Наблюдатель выключен (SCAN_WATCHER_ENABLED=false) — сам он ничего не возьмёт.")
	}
	items, err := r.ItemsAwaitingScan(ctx, cfg.ScanWatcherBatch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "выборка не удалась: %v\n", err)
		return 1
	}
	if len(items) == 0 {
		fmt.Println("Пакетов без отчётов нет — наблюдателю нечего делать.")
		fmt.Println("Если отчёта не хватает по конкретному пакету: moderation scan --why <id>")
		return 0
	}
	fmt.Printf("Наблюдатель возьмёт в работу %d пакет(ов) (не больше %d за проход, интервал %s):\n",
		len(items), cfg.ScanWatcherBatch, cfg.ScanWatcherInterval)
	for _, id := range items {
		fmt.Printf("  request_item #%d\n", id)
	}
	return 0
}

// explainItem — почему по пакету нет отчёта. Отвечает на вопрос, с которого
// начинается любое разбирательство, и отвечает конкретно: не «что-то не так»,
// а какого именно условия не хватает.
func explainItem(ctx context.Context, r *repo.Repo, itemID int64) int {
	e, err := r.ScanEligibilityOf(ctx, itemID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "не удалось разобраться: %v\n", err)
		return 1
	}
	fmt.Printf("request_item #%d\n", itemID)
	if !e.Exists {
		fmt.Println("  пакета с таким id нет")
		return 1
	}
	fmt.Printf("  статус заявки по пакету: %s\n", e.ItemStatus)
	if e.CurrentStep != "" {
		fmt.Printf("  текущий шаг: %s\n", e.CurrentStep)
	}
	if e.DownloadResult == "" {
		fmt.Println("  шаг скачивания: не выполнялся")
	} else {
		fmt.Printf("  шаг скачивания: %s\n", e.DownloadResult)
	}
	if len(e.Reports) == 0 {
		fmt.Println("  отчёты: нет ни одного")
	} else {
		fmt.Printf("  отчёты: %s\n", strings.Join(e.Reports, ", "))
	}
	fmt.Printf("\n  Наблюдатель возьмёт этот пакет: %v — %s\n", e.Eligible(), e.Reason())
	if e.Eligible() {
		fmt.Println("  Если отчёта всё равно нет — смотрите логи api-go: прогон падает,")
		fmt.Println("  и причина написана там (docker compose logs api-go | grep наблюдатель).")
	}
	return 0
}
