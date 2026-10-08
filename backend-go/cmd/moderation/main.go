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
	"moderation/internal/crypto"
	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/gitlab"
	"moderation/internal/maintenance"
	"moderation/internal/osv"
	"moderation/internal/policy"
	"moderation/internal/queue"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
	"moderation/internal/resolve"
)

func main() {
	logger := newLogger(os.Getenv)

	// Подкоманды. Без аргументов — HTTP-сервер (поведение по умолчанию не
	// меняется: так сервис запускается из docker-compose).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "scan":
			os.Exit(runScan(os.Args[2:], logger))
		case "worker":
			os.Exit(runWorker(os.Args[2:], logger))
		case "migrate":
			os.Exit(runMigrate(os.Args[2:], logger))
		case "schema":
			os.Exit(runSchemaCheck(os.Args[2:], logger))
		case "maintenance":
			os.Exit(runMaintenance(os.Args[2:], logger))
		case "bootstrap":
			os.Exit(runBootstrap(os.Args[2:], logger))
		case "import-packages":
			os.Exit(runImportPackages(os.Args[2:], logger))
		case "service-account":
			os.Exit(runServiceAccount(os.Args[2:], logger))
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
	settingsChanged := watchStoredSettings(ctx, pool, logger)
	applyStoredSettings(ctx, pool, cfg, logger)

	options, blacklist, _ := buildOptions(cfg, pool, logger)
	_ = blacklist // политики попадают в конвейер вместе с переносом шагов 0-3
	if options.Auth != nil && options.Auth.Auth != nil && options.Auth.Auth.SessionRepo != nil {
		startLoginThrottleCleanup(ctx, options.Auth.Auth.SessionRepo, logger)
	}

	// Сверка схемы с тем, что пишет код. Не фатально — сервис обязан отвечать
	// health и отдавать чтение даже на неполной схеме, — но громко: иначе
	// расхождение всплывает как случайная ошибка при нажатии кнопки. Так и
	// было: кнопка закрытия заявки отвечала 500, потому что в базе не
	// применили миграцию со статусом `cancelled`, и понять это по ответу
	// было невозможно.
	checkSchema(ctx, pool, logger)

	// Отдельный watcher отчётов больше не запускается. Раньше он был мостом,
	// пока заявки выполнял Python-конвейер, а отчёты умел строить только Go.
	// Теперь sandbox_scan — штатный шаг Go-конвейера; параллельный watcher
	// создавал отчёт раньше самого шага и мог дважды отправить один артефакт в
	// песочницу. Команда `moderation scan --item N` оставлена для диагностики.
	if cfg.ScanWatcherEnabled {
		logger.Warn("SCAN_WATCHER_ENABLED игнорируется: отчёты создаёт штатный шаг конвейера; " +
			"для ручной диагностики используйте `moderation scan --item N`")
	}

	// Сторож и ручной проход собираются до роутера: иначе условный маршрут
	// /admin/queue-sweep не подключится и кнопка получит 404. При изменении
	// web-настроек поколение сторожа заменяется вместе с роутером.
	watchdogs := &watchdogManager{}
	watchdogs.Replace(prepareWatchdog(ctx, cfg, pool, &options, logger), 10*time.Second)
	runtimeHandler := newSwappableHandler(api.NewRouter(pool, options))
	reloadAPIOnStoredSettings(ctx, settingsChanged, pool, runtimeHandler, watchdogs, logger)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: runtimeHandler,
	}

	go func() {
		logger.Info("сервис запущен", "addr", cfg.ListenAddr, "env", cfg.AppEnv)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP-сервер завершился с ошибкой", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("завершаю работу HTTP-сервиса")
	// Пока сторож возвращает прерванный пакет в очередь, HTTP listener ещё
	// открыт. Это убирает прежнее десятисекундное окно 502 при остановке.
	watchdogs.Stop(10 * time.Second)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("ошибка при остановке HTTP-сервера", "error", err)
	}
}

// startLoginThrottleCleanup обслуживает таблицу защиты входа от перебора:
// счётчики подбора пароля общие для всех реплик, но отработавшие строки не
// накапливаются в Postgres бесконечно.
func startLoginThrottleCleanup(ctx context.Context, store *repo.Repo, logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, err := store.PruneLoginThrottle(ctx)
				if err != nil {
					logger.Warn("не удалось очистить ограничения входа", "error", err)
				} else if removed > 0 {
					logger.Debug("старые ограничения входа удалены", "rows", removed)
				}
			}
		}
	}()
}

func usage() {
	fmt.Fprint(os.Stderr, `Сервис модерации пакетов (Go-версия).

Использование:
  moderation [serve]          HTTP-сервер: health, метрики, выдача отчётов
  moderation scan --item N    прогнать сканеры содержимого по пакету заявки N
  moderation scan --pending   какие пакеты подходят для ручного прогона
  moderation scan --why N     почему по пакету N нет отчёта
  moderation worker           обработка очереди конвейера
  moderation worker --once    разобрать очередь и выйти
  moderation migrate          накатить миграции (--status — что применено,
                              --down NNNN — откатить новее указанной,
                              --baseline NNNN — отметить уже накатанное
                              применённым, НЕ выполняя: для стенда, где схему
                              накатывали вручную до появления учёта)
  moderation schema           сверить схему базы с кодом: чего не хватает и
                              какую миграцию накатить
  moderation bootstrap        первичная настройка: справочники менеджеров и
                              лицензий, проверка репозиториев артефактори
                              (--demo — демо-данные стенда, --service-password —
                              пароль демо-учёток, --repositories=false —
                              не проверять репозитории)
  moderation import-packages  разовый импорт package_list.txt как уже одобренных
                              (--file, --manager, --actor, --origin, --dry-run)
  moderation service-account  сервисная учётка для CI (--username, --roles;
                              пароль — через MODERATION_SERVICE_PASSWORD или
                              стандартный ввод)
  moderation maintenance      прогнать регламентные задачи разово: снять
                              истёкший карантин, убрать временное хранилище,
                              загрузить снапшот базы уязвимостей
                              (--quarantine / --cleanup / --osv-sync / --rescan —
                              только одну из них, --force — перезагрузить снапшот)

Конфигурация — через переменные окружения, см. backend-go/README.md.
Обязательна DATABASE_URL; для отчётов, промежуточной зоны и публикации —
ARTIFACT_BASE_URL и ARTIFACT_REPO_*.
`)
}

// buildOptions собирает зависимости HTTP-маршрутов.
//
// Вынесено из main отдельной функцией именно чтобы её можно было проверить
// тестом: маршруты уже один раз уехали в релиз объявленными, но не
// подключёнными здесь — роутер их знал, а бинарник не отдавал, и снаружи это
// выглядело как 404 на работающем сервисе.
// buildOptions собирает обработчики API. Третьим значением возвращает
// хранилища: их же использует наблюдатель сканирования, и собирать подключение
// к артефактори второй раз ради него незачем. nil — хранилища не настроены,
// и тогда ни отчёты, ни наблюдатель не поднимаются.
func buildOptions(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) (api.Options, *policy.Blacklist, *stores) {
	var options api.Options
	r := repo.New(pool)
	var sessionRepo *repo.Repo
	if pool != nil {
		sessionRepo = r
		// Env только впервые заполняет OIDC singleton, после чего
		// настройки меняются через web и хранятся в Postgres.
		seedIssuer := cfg.BrowserIssuer()
		if err := r.SeedOIDCSettings(context.Background(), repo.OIDCSettings{
			Enabled: cfg.OIDCEnabled, Issuer: seedIssuer, ClientID: cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret, PublicBaseURL: cfg.OIDCPublicBaseURL,
			ButtonLabel: cfg.OIDCButtonLabel,
		}); err != nil {
			logger.Warn("OIDC-настройки из env не перенесены", "error", err)
		}
		if cfg.BootstrapAdminPassword != "" {
			if count, err := r.CountUsers(context.Background()); err != nil {
				logger.Warn("первый администратор не проверен", "error", err)
			} else if count == 0 {
				hash, hashErr := auth.HashPassword(cfg.BootstrapAdminPassword)
				if hashErr == nil {
					_, hashErr = r.CreateLocalUser(context.Background(), cfg.BootstrapAdminUsername,
						"", "", hash, []string{"admin"}, time.Now().UTC())
				}
				if hashErr != nil {
					logger.Error("первый администратор не создан", "error", hashErr)
				}
			}
		}
	}
	// Клиент тот же, что у хранилищ: реестры, артефактори и песочница ходят
	// через один корпоративный прокси, и разные таймауты у них означали бы
	// разное поведение при одной и той же недоступности сети.
	reg := newRegistry(cfg, newHTTPClient())

	// Проверка токенов. Собирается всегда: маршрут /auth/config нужен SPA даже
	// тогда, когда войти некуда — по нему интерфейс и объясняет, что вход не
	// настроен. За JWKS сервис идёт лениво, при первом токене, поэтому
	// недоступный на старте Keycloak сервис не роняет.
	options.Auth = &api.AuthHandler{
		Auth: &api.Auth{
			// Ограничение частоты — после опознания пользователя: считаем по
			// нему, а не по адресу, за которым сидит весь офис.
			RateLimit:   api.NewRateLimit(cfg.RateLimitPerMinute),
			Verifier:    auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil),
			Repo:        r,
			SessionRepo: sessionRepo,
			RefreshTTL:  cfg.LocalRefreshTokenTTL,
			RuntimeOIDC: api.NewRuntimeOIDCVerifier(sessionRepo, cfg),
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
	//
	// Держатель, а не две загруженные структуры: POST /api/v1/admin/reload
	// перечитывает файлы без перезапуска сервиса, и всё, что читает политики,
	// обязано читать их через него — иначе часть сервиса продолжит работать
	// по правилам, которых на диске уже нет.
	policies := policy.NewHolder(cfg.BlacklistFile, cfg.AllowedLicensesFile)
	licenses, blacklist := policies.Licenses(), policies.Blacklist()
	if licenses.Failed() {
		logger.Error("справочник лицензий не загружен — каждый пакет уйдёт юристам",
			"path", licenses.Path, "error", licenses.Err)
	} else {
		logger.Info("справочник лицензий загружен", "path", licenses.Path,
			"разрешено", len(licenses.Allowed), "запрещено", len(licenses.Forbidden))
	}
	if blacklist.Failed() {
		logger.Error("правила blacklist не загружены — запрет проверить нельзя, пакеты уйдут DevSecOps",
			"path", blacklist.Path, "error", blacklist.Err)
	} else {
		logger.Info("правила blacklist загружены", "path", blacklist.Path, "правил", len(blacklist.Rules))
	}
	options.Licenses = &api.LicensesHandler{Policies: policies}
	// Админка собирается ниже, вместе с очередью: экран «Настройка» показывает
	// её состояние, а очередь создаётся после обработчиков заявок.

	// Хранилище отчётов необязательно: без него сервис поднимается и отвечает
	// health, просто маршруты отчётов не подключаются. Падать на старте из-за
	// отчётов нельзя — иначе недоступное артефактори роняет весь сервис.
	// Доступность репозитория отчётов проверяется по-настоящему, а не по
	// «настройка не пустая»: у ARTIFACT_BASE_URL есть значение по умолчанию, и
	// без проверки маршруты отчётов подключались бы всегда, в том числе там,
	// где артефактори не поднято или репозитория не существует. Тогда вместо
	// честного «выдача отчётов отключена» в логе пользователь получал бы
	// ошибку на каждой попытке открыть отчёт.
	st, storesErr := newStores(cfg, newHTTPClient())
	if storesErr == nil {
		probe, cancel := context.WithTimeout(context.Background(), storeProbeTimeout)
		storesErr = st.Reports.EnsureBucket(probe)
		cancel()
	}
	if storesErr != nil {
		logger.Error("хранилище отчётов недоступно, выдача отчётов отключена",
			"артефактори", cfg.ArtifactBaseURL, "репозиторий", cfg.ArtifactRepoReports,
			"error", storesErr)
		st = nil
	} else {
		options.Reports = &api.ReportsHandler{Repo: repo.New(pool), Storage: st.Reports}
		options.SBOMs = &api.SBOMsHandler{Repo: repo.New(pool), Storage: st.Reports}
		logger.Info("хранилище отчётов подключено",
			"артефактори", cfg.ArtifactBaseURL, "репозиторий", cfg.ArtifactRepoReports)
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
				baseURL, repoName := cfg.ArtifactInstallLocation(manager)
				return plugin.InstallCommand(registry.Ref{
					Manager: manager, Name: name, DisplayName: displayName,
					Version: version, RawVersion: rawVersion,
				}, baseURL, repoName)
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
	decisionsService := &decisions.Service{
		Repo: r,
		Resume: func(ctx context.Context, item *domain.RequestItem, fromStep string) error {
			return pipelineQueue.Enqueue(ctx, item.ID, fromStep)
		},
	}
	options.Decisions = &api.DecisionsHandler{
		Repo: r, Decisions: decisionsService, Policies: policies, HTTP: newHTTPClient(),
	}

	// Экран «Настройка» и журнал аудита.
	//
	// Снапшот уязвимостей и очередь передаются те же, что у конвейера: экран
	// обязан показывать состояние ТОГО, что работает, а не отдельной копии.
	admin := &api.AdminHandler{
		Policies: policies, Repo: r, Cfg: cfg,
		Index: osv.NewSnapshotIndex(cfg.OSVLocalDBPath),
		Queue: pipelineQueue,
	}
	if st != nil {
		// Ручной запуск синхронизации подключается, только когда есть чем её
		// выполнить: кнопка, отвечающая «не настроено», хуже отсутствующей.
		maintenanceService := &maintenance.Service{
			Repo: r, Storage: st.Staging, Artifacts: st.Artifacts, Logger: logger,
			Decisions: decisionsService,
		}
		osvCfg := osvConfig(cfg)
		admin.OSVSync = func(ctx context.Context, force bool) (maintenance.SyncResult, error) {
			return maintenanceService.SyncOSVSnapshot(ctx, osvCfg, force)
		}
	}
	options.Admin = admin

	// GitLab — только чтение: подключение из профиля и чтение файла
	// зависимостей из приватного проекта от имени пользователя.
	//
	// Ключ шифрования токенов разбирается здесь: без него подключать GitLab
	// нельзя (токен пришлось бы хранить открытым), но сервис поднимается —
	// интеграцией пользуется меньшинство, и падать из-за неё нельзя.
	fernet, fernetErr := crypto.New(cfg.FernetKey)
	if fernetErr != nil && cfg.GitlabURL != "" {
		logger.Warn("подключение GitLab работать не будет", "error", fernetErr)
	}
	options.Gitlab = &api.GitlabHandler{
		Gitlab: &gitlab.Service{
			Cfg: gitlab.Config{
				BaseURL: cfg.GitlabURL, ClientID: cfg.GitlabOAuthClientID,
				ClientSecret: cfg.GitlabOAuthSecret, RedirectURI: cfg.GitlabRedirectURI,
				Fernet: fernet, HTTP: newHTTPClient(),
			},
			Store: r,
		},
		Repo: r, Registry: reg, Cfg: cfg, Requests: options.Requests,
	}
	// Отзыв пакета — тот же сервис решений: отзыв обязан вести себя одинаково,
	// кем бы он ни был вызван, кнопкой в карточке или перепроверкой по новой
	// базе уязвимостей.
	options.Packages.Decisions = decisionsService
	if st != nil {
		options.Packages.Artifacts = st.Artifacts
	}

	return options, blacklist, st
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
