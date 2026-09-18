// Точка входа сервиса модерации пакетов (Go-версия).
//
// Режим на сейчас — только "api" (HTTP-сервер). Режим "worker" появится вместе
// с очередью на NATS/Valkey (docs/migration-to-go.md, фаза 6); тогда же — решить
// открытый вопрос "один бинарник --mode=api|worker|all (как sentrix) или три
// отдельных" и обновить этот файл.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/queue"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
	"moderation/internal/resolve"
	"moderation/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Подкоманды. Без аргументов — HTTP-сервер (поведение по умолчанию не
	// меняется: так сервис запускается из docker-compose).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "scan":
			os.Exit(runScan(os.Args[2:], logger))
		case "worker":
			os.Exit(runWorker(os.Args[2:], logger))
		case "schema":
			os.Exit(runSchemaCheck(os.Args[2:], logger))
		case "serve":
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "-h", "--help", "help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", os.Args[1])
			usage()
			os.Exit(2)
		}
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	options, blacklist := buildOptions(cfg, pool, logger)
	_ = blacklist // политики попадают в конвейер вместе с переносом шагов 0-3

	// Сверка схемы с тем, что пишет код. Не фатально — сервис обязан отвечать
	// health и отдавать чтение даже на неполной схеме, — но громко: иначе
	// расхождение всплывает как случайная ошибка при нажатии кнопки. Так и
	// было: кнопка закрытия заявки отвечала 500, потому что в базе не
	// применили миграцию со статусом `cancelled`, и понять это по ответу
	// было невозможно.
	checkSchema(ctx, pool, logger)

	// Наблюдатель сканирования. Требует хранилища: отчёты некуда класть без
	// него, и запускать прогон впустую незачем.
	//
	// Каждая ветка что-то пишет в лог. Раньше случай «наблюдатель включён, но
	// хранилища нет» не писал НИЧЕГО: отчёты не появлялись сами, в логах было
	// пусто, и снаружи это выглядело как «автоматика не работает» без единой
	// зацепки. Молчаливо не запуститься фоновая работа не имеет права.
	switch {
	case !cfg.ScanWatcherEnabled:
		logger.Info("наблюдатель сканирования выключен (SCAN_WATCHER_ENABLED=false) — " +
			"отчёты появятся только после `moderation scan`")
	case options.Reports == nil:
		logger.Error("наблюдатель сканирования НЕ запущен: не настроено хранилище отчётов " +
			"(S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY) — класть отчёты некуда")
	default:
		w := &watcher{
			repo: options.Reports.Repo, storage: options.Reports.Storage,
			cfg: cfg, logger: logger,
			interval: cfg.ScanWatcherInterval, batch: cfg.ScanWatcherBatch,
			itemTimeout: cfg.ScanWatcherItemTimeout,
		}
		go w.run(ctx)
	}

	// Сторож очереди конвейера. Подбирает пакеты, которые не забрал выделенный
	// воркер, — см. cmd/moderation/watchdog.go, там же причина, почему он
	// обязателен, а не «на всякий случай».
	//
	// Каждая ветка что-то пишет в лог по той же причине, что и у наблюдателя
	// сканирования: страховка, которая не запустилась молча, снаружи
	// неотличима от работающей.
	switch {
	case !cfg.PipelineWatchdogEnabled:
		logger.Warn("сторож очереди выключен (PIPELINE_WATCHDOG_ENABLED=false) — " +
			"пакеты разбирает только выделенный воркер; если он не поднят, заявки будут ждать вечно")
	default:
		worker, err := newPipelineWorker(cfg, pool, logger)
		if err != nil {
			logger.Error("сторож очереди НЕ запущен — пакеты разберёт только выделенный воркер",
				"error", err)
			break
		}
		go newWatchdog(worker, cfg.PipelineWatchdogInterval, cfg.PipelineStuckAfter, logger).run(ctx)
	}

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: api.NewRouter(pool, options),
	}

	go func() {
		logger.Info("сервис запущен", "addr", cfg.ListenAddr, "env", cfg.AppEnv)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP-сервер завершился с ошибкой", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("получен сигнал остановки, завершаю работу")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("ошибка при остановке HTTP-сервера", "error", err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Сервис модерации пакетов (Go-версия).

Использование:
  moderation [serve]          HTTP-сервер: health, метрики, выдача отчётов
  moderation scan --item N    прогнать сканеры содержимого по пакету заявки N
  moderation scan --pending   что фоновый наблюдатель возьмёт в работу
  moderation scan --why N     почему по пакету N нет отчёта
  moderation worker           обработка очереди конвейера
  moderation worker --once    разобрать очередь и выйти
  moderation schema           сверить схему базы с кодом: чего не хватает и
                              какую миграцию накатить

Конфигурация — через переменные окружения, см. backend-go/README.md.
Обязательна DATABASE_URL; для отчётов нужны также S3_*.
`)
}

// buildOptions собирает зависимости HTTP-маршрутов.
//
// Вынесено из main отдельной функцией именно чтобы её можно было проверить
// тестом: маршруты уже один раз уехали в релиз объявленными, но не
// подключёнными здесь — роутер их знал, а бинарник не отдавал, и снаружи это
// выглядело как 404 на работающем сервисе.
func buildOptions(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) (api.Options, *policy.Blacklist) {
	var options api.Options
	r := repo.New(pool)
	reg := registry.New(registry.Config{
		PyPIURL: cfg.RegistryPyPIURL, NpmURL: cfg.RegistryNpmURL,
		GoProxy: cfg.RegistryGoProxy, NuGetURL: cfg.RegistryNuGetURL,
	})

	// Проверка токенов. Собирается всегда: маршрут /auth/config нужен SPA даже
	// тогда, когда войти некуда — по нему интерфейс и объясняет, что вход не
	// настроен. За JWKS сервис идёт лениво, при первом токене, поэтому
	// недоступный на старте Keycloak сервис не роняет.
	options.Auth = &api.AuthHandler{
		Auth: &api.Auth{
			Verifier: auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil),
			Repo:     repo.New(pool),
		},
		Cfg: cfg,
	}
	if cfg.OIDCIssuer == "" && !cfg.LocalAuthEnabled {
		logger.Warn("вход не настроен: не задан OIDC_ISSUER и выключен LOCAL_AUTH_ENABLED — " +
			"закрытые маршруты будут отвечать 401 всем")
	}
	if cfg.AppEnv == "prod" && cfg.LocalAuthEnabled {
		// Не отказ в запуске, а громкое предупреждение: fallback-вход по
		// паролю в prod — осознанное решение администратора, но молчать о нём
		// нельзя.
		logger.Warn("в prod включён вход по логину и паролю (LOCAL_AUTH_ENABLED=true)")
	}

	// Политики из файлов. Сервис поднимается и с непрочитанным файлом, но
	// молча это не проходит: шаги blacklist и license в таком случае отдают
	// решение человеку, а не пропускают пакет (см. internal/pipeline/steps.go).
	licenses := policy.LoadLicensePolicy(cfg.AllowedLicensesFile)
	if licenses.Failed() {
		logger.Error("справочник лицензий не загружен — каждый пакет уйдёт юристам",
			"path", licenses.Path, "error", licenses.Err)
	} else {
		logger.Info("справочник лицензий загружен", "path", licenses.Path,
			"разрешено", len(licenses.Allowed), "запрещено", len(licenses.Forbidden))
	}
	blacklist := policy.LoadBlacklist(cfg.BlacklistFile)
	if blacklist.Failed() {
		logger.Error("правила blacklist не загружены — запрет проверить нельзя, пакеты уйдут DevSecOps",
			"path", blacklist.Path, "error", blacklist.Err)
	} else {
		logger.Info("правила blacklist загружены", "path", blacklist.Path, "правил", len(blacklist.Rules))
	}
	options.Licenses = &api.LicensesHandler{Policy: licenses}

	// Хранилище отчётов необязательно: без него сервис поднимается и отвечает
	// health, просто маршруты отчётов не подключаются. Падать на старте из-за
	// отчётов нельзя — иначе недоступный MinIO роняет весь сервис.
	if cfg.S3Endpoint != "" {
		store, err := storage.NewS3(storage.S3Config{
			Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region,
			VirtualHost: cfg.S3VirtualHost,
		})
		if err != nil {
			logger.Error("хранилище отчётов не настроено, выдача отчётов отключена", "error", err)
		} else {
			options.Reports = &api.ReportsHandler{Repo: repo.New(pool), Storage: store}
			logger.Info("хранилище отчётов подключено", "endpoint", cfg.S3Endpoint, "bucket", cfg.S3Bucket)
		}
	} else {
		logger.Warn("S3_ENDPOINT не задан — выдача отчётов о сканировании отключена")
	}

	options.Packages = &api.PackagesHandler{Repo: r, Registry: reg, Cfg: cfg}
	// Очередь конвейера одна на весь сервис: и создание заявок, и решения
	// ролей кладут работу в неё же.
	pipelineQueue := queue.New(pool, cfg.PipelineStuckAfter*3)

	options.Requests = &api.RequestsHandler{
		Repo: r, Registry: reg, Cfg: cfg,
		Requests: &requests.Service{
			Repo: r, Registry: reg,
			Limits: requests.Limits{
				MaxPackages: cfg.MaxPackagesPerRequest, MaxUploadSize: cfg.MaxUploadSizeBytes,
			},
			// Раскрытие зависимостей ходит в те же реестры и тем же клиентом,
			// что и остальной сервис: один прокси, один таймаут, один
			// источник правды про доступность реестра.
			Resolver: resolve.New(reg, resolve.Options{
				MaxDepth:        cfg.ResolveMaxDepth,
				MaxNodes:        cfg.ResolveMaxPackages,
				IncludeOptional: cfg.ResolveIncludeOptional,
				Concurrency:     cfg.ResolveConcurrency,
			}, logger),
			InstallCommand: func(manager, name, displayName, version, rawVersion string) string {
				plugin, err := reg.Get(manager)
				if err != nil {
					return ""
				}
				return plugin.InstallCommand(registry.Ref{
					Manager: manager, Name: name, DisplayName: displayName,
					Version: version, RawVersion: rawVersion,
				}, cfg.ArtifactBaseURL, cfg.ArtifactRepo(manager))
			},
			OnAuditError: func(err error) {
				logger.Error("аудит создания заявки не записан", "error", err)
			},
		},
		Queue: pipelineQueue,
	}
	options.Queues = &api.QueuesHandler{Repo: r}
	options.Comments = &api.CommentsHandler{Repo: r, Cfg: cfg}
	options.Notifications = &api.NotificationsHandler{Repo: r}

	// Решения ролей. Возобновление конвейера уходит в очередь: воркер
	// заберёт пакет и продолжит с нужного шага. Прямой прогон здесь, в
	// процессе API, был бы вторым движком конвейера — и двумя реализациями,
	// пишущими шаги одного пакета.
	options.Decisions = &api.DecisionsHandler{
		Repo: r,
		Decisions: &decisions.Service{
			Repo: r,
			Resume: func(ctx context.Context, item *domain.RequestItem, fromStep string) error {
				return pipelineQueue.Enqueue(ctx, item.ID, fromStep)
			},
		},
	}

	return options, blacklist
}

// checkSchema сверяет CHECK-ограничения базы со значениями, которые пишет код,
// и называет миграцию, которой не хватает.
func checkSchema(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	gaps, err := repo.New(pool).MissingSchemaObjects(checkCtx)
	if err != nil {
		logger.Warn("схему сверить не удалось — расхождение с миграциями останется незамеченным",
			"error", err)
		return
	}
	if len(gaps) == 0 {
		logger.Info("схема базы согласована с кодом")
		return
	}
	for _, gap := range gaps {
		logger.Error("СХЕМА БАЗЫ УСТАРЕЛА: "+gap.String(),
			"таблица", gap.Table, "столбец", gap.Column,
			"значение", gap.Value, "миграция", gap.Migration)
	}
	logger.Error("часть действий будет отвечать ошибкой, пока миграции не накатят",
		"пробелов", len(gaps))
}
