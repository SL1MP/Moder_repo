package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/seeds"
)

// Команды первичной настройки. Порт backend/app/cli.py: bootstrap,
// import-package-list, create-service-account.
//
// Все три — разовые: их запускают при заведении стенда или один раз при
// переезде со списков в GitLab. Поэтому они не живут внутри сервиса и не
// вызываются по HTTP: то, что выполняется однажды и меняет содержимое базы
// целиком, должно требовать доступа к консоли.

// bootstrapEnv — общая для всех трёх команд подготовка: конфигурация,
// подключение к базе, контекст, снимаемый по Ctrl+C.
//
// Вынесено отдельно, потому что каждая из команд без этого повторяла бы
// двадцать строк открытия пула, а разъехавшаяся обработка ошибки подключения
// означала бы, что одна команда говорит «не удалось подключиться к Postgres»,
// а другая падает с паникой на nil-пуле.
type bootstrapEnv struct {
	cfg    *config.Config
	pool   *pgxpool.Pool
	repo   *repo.Repo
	seeds  *seeds.Service
	ctx    context.Context
	stop   context.CancelFunc
	logger *slog.Logger
}

func openBootstrapEnv(logger *slog.Logger) (*bootstrapEnv, error) {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("конфигурация невалидна: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		stop()
		return nil, fmt.Errorf("не удалось подключиться к Postgres: %w", err)
	}
	r := repo.New(pool)
	return &bootstrapEnv{
		cfg: cfg, pool: pool, repo: r, ctx: ctx, stop: stop, logger: logger,
		seeds: &seeds.Service{
			Repo:     r,
			Registry: newRegistry(cfg, newHTTPClient()),
			Policies: policy.NewHolder(cfg.BlacklistFile, cfg.AllowedLicensesFile),
		},
	}, nil
}

func (e *bootstrapEnv) close() {
	e.pool.Close()
	e.stop()
}

// runBootstrap — первичная настройка стенда.
func runBootstrap(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	demo := fs.Bool("demo", false, "завести демо-данные (учётки, примеры пакетов, заявка в карантине)")
	repositories := fs.Bool("repositories", true, "проверить доступность репозиториев артефактори")
	servicePassword := fs.String("service-password", "",
		"пароль демо-учёток; только для стенда с LOCAL_AUTH_ENABLED=true")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	env, err := openBootstrapEnv(logger)
	if err != nil {
		logger.Error("подготовка не выполнена", "error", err)
		return 1
	}
	defer env.close()

	code := 0
	managers, err := env.seeds.Managers(env.ctx)
	if err != nil {
		logger.Error("справочник менеджеров не заполнен", "error", err)
		code = 1
	} else {
		// Считаем по таблице, а не по списку кодов в коде: вопрос, на который
		// отвечает эта строка, — «что увидит интерфейс», а он читает таблицу.
		inDB, err := env.repo.ListManagers(env.ctx)
		if err != nil {
			logger.Error("справочник менеджеров не прочитан", "error", err)
			code = 1
		} else {
			fmt.Printf("Менеджеры пакетов: в справочнике %d, заведено новых %d\n",
				len(inDB), managers)
		}
	}

	licenses, err := env.seeds.Licenses(env.ctx)
	switch {
	case err != nil:
		// Непрочитанный справочник — не «ноль лицензий». Пропускать его молча
		// нельзя: автодополнение в карточке пакета окажется пустым, и
		// разработчик решит, что заявить лицензию нечем.
		var notLoaded *seeds.ErrLicensesNotLoaded
		if errors.As(err, &notLoaded) {
			fmt.Fprintf(os.Stderr, "Справочник лицензий не заполнен: %v\n", err)
		} else {
			logger.Error("справочник лицензий не заполнен", "error", err)
		}
		code = 1
	default:
		inDB, err := env.repo.ListLicenses(env.ctx)
		if err != nil {
			logger.Error("справочник лицензий не прочитан", "error", err)
			code = 1
		} else {
			fmt.Printf("Лицензии: в справочнике %d, заведено новых %d\n", len(inDB), licenses)
		}
	}

	if *demo {
		hash := ""
		if *servicePassword != "" {
			hash, err = auth.HashPassword(*servicePassword)
			if err != nil {
				logger.Error("пароль демо-учёток не захеширован", "error", err)
				return 1
			}
		}
		counts, err := env.seeds.SeedDemoData(env.ctx, hash)
		if err != nil {
			logger.Error("демо-данные не заведены", "error", err)
			code = 1
		} else {
			fmt.Printf("Демо-данные: учёток %d, одобренных пакетов %d, заявок %d\n",
				counts.Users, counts.Approved, counts.Requests)
			if hash != "" {
				fmt.Println("  Демо-учётки получили пароль — вход работает только при LOCAL_AUTH_ENABLED=true")
			}
		}
	} else if *servicePassword != "" {
		// Пароль без --demo не применить: учёток, которым его выдавать, ещё
		// нет. Промолчать значило бы отчитаться об успехе, не сделав того,
		// ради чего команду запустили.
		fmt.Fprintln(os.Stderr, "--service-password указан без --demo: демо-учётки не заводились, пароль не применён")
		code = 1
	}

	if *repositories {
		if !checkRepositories(env) {
			code = 1
		}
	}
	return code
}

// checkRepositories проверяет, что настроенные репозитории артефактори
// существуют и отвечают.
//
// Именно проверяет, а не создаёт, в отличие от python-версии. Создание там
// умело только Nexus (его админский REST API), для JFrog Artifactory
// эквивалента нет вовсе, а токен сервиса в промышленном контуре прав на
// заведение репозиториев не имеет и иметь не должен. Полезен же здесь не факт
// создания, а ответ на вопрос «куда сервис будет класть пакеты и доедет ли он
// туда» — и на него отвечает проверка.
//
// Проверяется корень репозитория, а не конкретный файл: пустой репозиторий —
// штатное состояние только что заведённого стенда, и путать его с
// отсутствующим нельзя.
func checkRepositories(env *bootstrapEnv) bool {
	store, err := newArtifactStore(env.cfg, newHTTPClient())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Артефактори не настроено: %v\n", err)
		return false
	}
	if store.DryRun() {
		fmt.Println("Артефактори в режиме dry-run (ARTIFACT_DRY_RUN=true) — проверка репозиториев пропущена")
		return true
	}

	// Порядок вывода устойчивый: список читают глазами и сравнивают между
	// стендами, а map в Go отдаёт ключи вразнобой.
	type target struct{ role, name string }
	targets := []target{
		{"промежуточная зона", env.cfg.ArtifactRepoStaging},
		{"отчёты", env.cfg.ArtifactRepoReports},
		{"снапшот OSV", env.cfg.ArtifactRepoOSV},
	}
	managers := make([]target, 0, len(env.cfg.ArtifactRepos))
	for manager, name := range env.cfg.ArtifactRepos {
		managers = append(managers, target{manager, name})
	}
	sort.Slice(managers, func(i, j int) bool { return managers[i].role < managers[j].role })
	targets = append(targets, managers...)

	fmt.Printf("Репозитории артефактори (%s, %s):\n", store.Kind(), env.cfg.ArtifactBaseURL)
	ok := true
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t.name == "" || seen[t.name] {
			continue
		}
		seen[t.name] = true
		ctx, cancel := context.WithTimeout(env.ctx, storeProbeTimeout)
		file, err := store.StatFile(ctx, t.name, "")
		cancel()
		switch {
		case err != nil:
			fmt.Printf("  %-24s %-24s ОШИБКА: %v\n", t.name, "("+t.role+")", err)
			ok = false
		case file == nil:
			fmt.Printf("  %-24s %-24s НЕ НАЙДЕН — заведите его в артефактори\n", t.name, "("+t.role+")")
			ok = false
		default:
			fmt.Printf("  %-24s %-24s есть\n", t.name, "("+t.role+")")
		}
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "Часть репозиториев недоступна: пакеты в них не опубликуются.")
	}
	return ok
}

// takeLeading отделяет первый позиционный аргумент от флагов.
//
// Нужен потому, что flag из стандартной библиотеки прекращает разбор на первом
// же аргументе без дефиса: `import-packages список.txt --manager pypi` без
// этого молча теряет --manager и падает с «нужен --manager», хотя он указан.
// Python-версия принимает путь именно так, и в чужих инструкциях команда
// записана в этом порядке.
func takeLeading(args []string) (leading string, rest []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// runImportPackages — разовый импорт существующего package_list.txt.
func runImportPackages(args []string, logger *slog.Logger) int {
	leading, args := takeLeading(args)
	fs := flag.NewFlagSet("import-packages", flag.ContinueOnError)
	file := fs.String("file", "", "файл со списком пакетов (по строке на пакет)")
	manager := fs.String("manager", "", "код пакетного менеджера: "+strings.Join(domain.ManagerCodes, " | "))
	actor := fs.String("actor", "", "логин учётной записи для журнала; пусто — импорт от имени CLI")
	origin := fs.String("origin", "", "источник списка, например gitlab:group/repo:package_list.txt")
	dryRun := fs.Bool("dry-run", false, "только разобрать файл и показать итог, ничего не записывая")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Путь можно указать и позиционно — так его передаёт python-версия, и
	// переучивать тех, у кого команда записана в инструкции, незачем.
	if *file == "" {
		if leading != "" {
			*file = leading
		} else if fs.NArg() > 0 {
			*file = fs.Arg(0)
		}
	}
	if *file == "" || *manager == "" {
		fmt.Fprintln(os.Stderr, "нужны --file и --manager")
		fs.PrintDefaults()
		return 2
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "файл не прочитан: %v\n", err)
		return 1
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	env, err := openBootstrapEnv(logger)
	if err != nil {
		logger.Error("подготовка не выполнена", "error", err)
		return 1
	}
	defer env.close()

	var user *domain.User
	if *actor != "" {
		user, err = env.repo.GetUserByUsername(env.ctx, *actor)
		if err != nil {
			logger.Error("учётная запись не прочитана", "error", err)
			return 1
		}
		if user == nil {
			// Не молчим и не подставляем «CLI»: имя в журнале — единственный
			// ответ на вопрос «кто внёс этот пакет как одобренный», и
			// подменить его тихо значит потерять этот ответ.
			fmt.Fprintf(os.Stderr, "учётная запись «%s» не найдена\n", *actor)
			return 1
		}
	}
	source := *origin
	if source == "" {
		source = *file
	}

	if *dryRun {
		return importDryRun(env, *manager, lines)
	}
	stats, err := env.seeds.ImportPackageList(env.ctx, *manager, lines, user, source)
	printImportStats(stats)
	if err != nil {
		logger.Error("импорт прерван", "error", err)
		return 1
	}
	if stats.Invalid > 0 {
		return 1
	}
	return 0
}

// importDryRun разбирает файл, ничего не записывая.
//
// Нужен именно этой команде: импорт переводит пакеты в «одобрен» без прогона
// конвейера, и запускать его вслепую по файлу, который в последний раз читали
// глазами год назад, — способ незаметно одобрить строку, случайно попавшую в
// список.
func importDryRun(env *bootstrapEnv, manager string, lines []string) int {
	plugin, err := env.seeds.Registry.Get(manager)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	parsed := 0
	var invalid []string
	for _, rawLine := range lines {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		if _, err := registry.ParseEntry(plugin, line); err != nil {
			invalid = append(invalid, line)
			continue
		}
		parsed++
	}
	fmt.Printf("Разбор без записи: распознано %d, не распознано %d\n", parsed, len(invalid))
	for _, line := range invalid {
		fmt.Printf("  не разобрано: %s\n", line)
	}
	if len(invalid) > 0 {
		return 1
	}
	return 0
}

func printImportStats(stats seeds.ImportStats) {
	fmt.Printf("Импортировано: %d, пропущено (уже одобрены): %d, с ошибкой формата: %d\n",
		stats.Imported, stats.Skipped, stats.Invalid)
	for _, line := range stats.InvalidLines {
		fmt.Printf("  не разобрано: %s\n", line)
	}
	if stats.Invalid > len(stats.InvalidLines) {
		fmt.Printf("  … и ещё %d строк\n", stats.Invalid-len(stats.InvalidLines))
	}
}

// runServiceAccount заводит сервисную учётную запись для CI.
func runServiceAccount(args []string, logger *slog.Logger) int {
	leading, args := takeLeading(args)
	fs := flag.NewFlagSet("service-account", flag.ContinueOnError)
	username := fs.String("username", "", "логин сервисной учётной записи")
	roles := fs.String("roles", "developer", "роли через запятую: "+strings.Join(domain.Roles, " | "))
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *username == "" {
		if leading != "" {
			*username = leading
		} else if fs.NArg() > 0 {
			*username = fs.Arg(0)
		}
	}
	if *username == "" {
		fmt.Fprintln(os.Stderr, "нужен --username")
		fs.PrintDefaults()
		return 2
	}

	roleList := splitRoles(*roles)
	if len(roleList) == 0 {
		fmt.Fprintln(os.Stderr, "нужна хотя бы одна роль")
		return 2
	}
	for _, role := range roleList {
		if !domain.Contains(domain.Roles, role) {
			fmt.Fprintf(os.Stderr, "неизвестная роль «%s»; известны: %s\n",
				role, strings.Join(domain.Roles, ", "))
			return 2
		}
	}

	password, err := readServicePassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	env, err := openBootstrapEnv(logger)
	if err != nil {
		logger.Error("подготовка не выполнена", "error", err)
		return 1
	}
	defer env.close()

	hash, err := auth.HashPassword(password)
	if err != nil {
		logger.Error("пароль не захеширован", "error", err)
		return 1
	}
	user, err := env.repo.UpsertServiceAccount(env.ctx, *username, roleList, hash, time.Now().UTC())
	if err != nil {
		logger.Error("сервисная учётная запись не заведена", "error", err)
		return 1
	}

	entityID := fmt.Sprintf("%d", user.ID)
	if err := env.repo.InsertAuditLog(env.ctx, domain.AuditLog{
		ActorName: "CLI", Action: "service_account_created", EntityType: "user",
		EntityID: &entityID,
		NewValue: map[string]any{"username": *username, "roles": roleList},
		Source:   "cli", CreatedAt: time.Now().UTC(),
	}); err != nil {
		// Учётка уже заведена, откатывать её поздно, но о непопавшей в журнал
		// выдаче доступа обязан узнать тот, кто её выдал.
		logger.Error("запись в журнал не создана", "error", err)
		return 1
	}

	fmt.Printf("Сервисная учётная запись «%s» готова, роли: %s\n",
		*username, strings.Join(roleList, ", "))
	if !env.cfg.LocalAuthEnabled {
		fmt.Fprintln(os.Stderr,
			"LOCAL_AUTH_ENABLED=false — вход по логину и паролю сейчас отключён, "+
				"учётка заведена, но войти по ней нельзя")
	}
	return 0
}

// servicePasswordEnv — переменная окружения с паролем сервисной учётки.
const servicePasswordEnv = "MODERATION_SERVICE_PASSWORD"

// readServicePassword берёт пароль из окружения или со стандартного ввода.
//
// Флага --password намеренно нет: значение флага видно в `ps` любому
// пользователю машины и остаётся в истории командной оболочки. Пароль
// сервисной учётки — это доступ к заведению заявок от имени CI, и раздавать
// его через список процессов нельзя.
func readServicePassword() (string, error) {
	if value := os.Getenv(servicePasswordEnv); value != "" {
		return value, nil
	}
	stat, err := os.Stdin.Stat()
	if err == nil && stat.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "Пароль (ввод виден на экране): ")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("пароль не задан: передайте его через %s или на стандартный ввод",
			servicePasswordEnv)
	}
	if err != nil && !errors.Is(err, os.ErrClosed) && password == "" {
		return "", fmt.Errorf("пароль не прочитан: %w", err)
	}
	return password, nil
}

func splitRoles(raw string) []string {
	var roles []string
	for _, part := range strings.Split(raw, ",") {
		if role := strings.TrimSpace(part); role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}
