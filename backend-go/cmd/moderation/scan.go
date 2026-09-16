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
	"time"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/registry"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *itemID <= 0 {
		fmt.Fprintln(os.Stderr, "укажите пакет заявки: moderation scan --item <id>")
		fmt.Fprintln(os.Stderr, "id виден в адресе карточки пакета и в ответе GET /api/v1/requests/{id}")
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

	store, err := storage.NewS3(storage.S3Config{
		Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region,
	})
	if err != nil {
		logger.Error("хранилище не настроено — отчёты некуда положить", "error", err)
		return 1
	}

	pc, err := buildScanContext(ctx, r, store, cfg)
	if err != nil {
		logger.Error("подготовка сканирования", "error", err)
		return 1
	}
	if err := loadItem(ctx, r, pc, *itemID); err != nil {
		logger.Error("пакет заявки не найден", "item", *itemID, "error", err)
		return 1
	}

	logger.Info("сканирую пакет",
		"item", *itemID, "package", pc.Package.DisplayName, "version", pc.Version.RawVersion)

	// Артефакт мог быть вычищен из карантинной зоны после публикации —
	// скачиваем заново тем же шагом конвейера.
	if err := ensureArtifact(ctx, r, pc, logger); err != nil {
		logger.Error("артефакт не получен", "error", err)
		return 1
	}

	failed := false
	for _, step := range []pipeline.Step{pipeline.BannerScanStep, pipeline.SastScanStep} {
		outcome, err := step.Run(ctx, pc)
		if err != nil {
			logger.Error("шаг завершился ошибкой", "step", step.Code(), "error", err)
			failed = true
			continue
		}
		report, err := r.GetScanReport(ctx, pc.Item.ID, step.Code())
		if err != nil {
			logger.Error("отчёт не прочитан", "step", step.Code(), "error", err)
			failed = true
			continue
		}
		if report == nil {
			// Шаг выключен настройкой — прогона не было, отчёта нет.
			logger.Info("отчёт не создан", "step", step.Code(), "причина", outcome.Message)
			continue
		}
		logger.Info("отчёт готов",
			"step", step.Code(), "состояние", report.State,
			"находок", report.FindingsTotal, "блокирующих", report.FindingsBlocking,
			"json", report.JSONKey, "html", report.HTMLKey)
	}

	if failed {
		return 1
	}
	fmt.Printf("\nОтчёты доступны:\n")
	for _, code := range domain.ScanReportStepCodes {
		fmt.Printf("  /api/v1/request-items/%d/reports/%s.html\n", *itemID, code)
	}
	fmt.Printf("  /api/v1/request-items/%d/reports   (список)\n", *itemID)
	return 0
}

// buildScanContext собирает конвейерный контекст со всеми зависимостями,
// кроме самого пакета: его подставляет loadItem.
func buildScanContext(_ context.Context, r *repo.Repo, store storage.Store, cfg *config.Config) (*pipeline.Context, error) {
	httpClient := &http.Client{Timeout: 60 * time.Second}
	reg := registry.New(registry.Config{
		PyPIURL: cfg.RegistryPyPIURL, NpmURL: cfg.RegistryNpmURL,
		GoProxy: cfg.RegistryGoProxy, NuGetURL: cfg.RegistryNuGetURL,
		HTTP: httpClient,
	})

	return &pipeline.Context{
		Config: pipeline.Config{
			MaxArtifactSizeBytes: cfg.MaxArtifactSizeBytes,
			BannerScanEnabled:    cfg.BannerScanEnabled,
			SASTEnabled:          cfg.SASTEnabled,
			SASTMinSeverity:      cfg.SASTMinSeverity,
			ScanMaxUnpackedBytes: cfg.ScanMaxUnpackedBytes,
			ScanMaxFiles:         cfg.ScanMaxFiles,
		},
		Deps: pipeline.Deps{
			Repo: r, Storage: store, Registry: reg,
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
	if artifact != nil && artifact.S3Key != nil && *artifact.S3Key != "" && artifact.S3DeletedAt == nil {
		if _, err := pc.Deps.Storage.Stat(ctx, *artifact.S3Key); err == nil {
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
