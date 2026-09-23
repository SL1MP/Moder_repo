package seeds

import (
	"context"
	"fmt"
	"time"

	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Демо-стенд: учётки, несколько одобренных пакетов и одна заявка, остановленная
// на карантине.
//
// Зачем это вообще есть: пустой сервис нечем показать и не на чем проверить
// интерфейс. Первый же экран после установки — «пакетов нет, заявок нет», и по
// нему нельзя сказать, работает сервис или просто молчит. Демо-заявка в
// карантине выбрана не случайно: это единственное состояние, в котором видно
// сразу всё — пройденные шаги, остановленный шаг и причина ожидания.
//
// Ничего из этого не должно попасть в промышленный контур, поэтому bootstrap
// заводит демо-данные только по явному флагу.

// DemoUsers — учётки стенда, по одной на роль.
var DemoUsers = []repo.DemoUser{
	{Username: "dev.ivanov", FullName: "Иванов Иван", Roles: []string{"developer"}, Email: "dev.ivanov@example.com"},
	{Username: "sec.petrov", FullName: "Петров Пётр", Roles: []string{"devsecops"}, Email: "sec.petrov@example.com"},
	{Username: "legal.sidorova", FullName: "Сидорова Анна", Roles: []string{"legal"}, Email: "legal.sidorova@example.com"},
	{Username: "admin", FullName: "Администратор сервиса", Roles: []string{"admin"}, Email: "admin@example.com"},
}

// demoApproved — пакеты, показываемые как давно одобренные.
var demoApproved = []struct{ Manager, Name, Version, SPDX string }{
	{"pypi", "requests", "2.31.0", "Apache-2.0"},
	{"pypi", "pydantic", "2.6.4", "MIT"},
	{"npm", "lodash", "4.17.21", "MIT"},
	{"go", "github.com/gin-gonic/gin", "v1.9.1", "MIT"},
	{"nuget", "Newtonsoft.Json", "13.0.3", "MIT"},
}

// demoRequestReason — метка демо-заявки. По ней же повторный bootstrap узнаёт
// свою заявку и не заводит вторую.
const demoRequestReason = "Демо-заявка: карантин"

// DemoCounts — что завели.
type DemoCounts struct {
	Users    int
	Approved int
	Requests int
}

// DemoUsers заводит учётки стенда.
//
// password непустой — учётки становятся сервисными и получают хеш пароля:
// иначе на стенде без каталога OIDC в сервис нечем войти. Пустой password
// оставляет уже выданные пароли как есть.
func (s *Service) SeedDemoUsers(ctx context.Context, passwordHash string) ([]domain.User, error) {
	users := make([]domain.User, 0, len(DemoUsers))
	for _, u := range DemoUsers {
		user, err := s.Repo.UpsertDemoUser(ctx, u, passwordHash)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}
	return users, nil
}

// SeedDemoData заводит демо-учётки, одобренные пакеты и заявку в карантине.
func (s *Service) SeedDemoData(ctx context.Context, passwordHash string) (DemoCounts, error) {
	var counts DemoCounts
	users, err := s.SeedDemoUsers(ctx, passwordHash)
	if err != nil {
		return counts, err
	}
	counts.Users = len(users)

	var author *domain.User
	for i := range users {
		if users[i].HasRole("developer") {
			author = &users[i]
			break
		}
	}
	if author == nil {
		return counts, fmt.Errorf("среди демо-учёток нет разработчика — заводить заявку не от кого")
	}

	now := s.now()
	published := now.Add(-200 * 24 * time.Hour)
	approved := now.Add(-30 * 24 * time.Hour)
	zero := 0.0
	for _, d := range demoApproved {
		version, err := s.demoVersion(ctx, d.Manager, d.Name, d.Version)
		if err != nil {
			return counts, err
		}
		if version.Status == "approved" {
			continue
		}
		if err := s.Repo.SetDemoVersion(ctx, version.ID, repo.DemoVersion{
			Status: "approved", LicenseSPDX: d.SPDX, LicenseSource: "registry",
			PublishedAt: &published, ApprovedAt: &approved, MaxVulnScore: &zero,
		}); err != nil {
			return counts, err
		}
		counts.Approved++
	}

	requests, err := s.demoQuarantineRequest(ctx, author, now)
	if err != nil {
		return counts, err
	}
	counts.Requests = requests

	if err := s.Repo.InsertAuditLog(ctx, domain.AuditLog{
		ActorName: "CLI", Action: "demo_data_seeded", EntityType: "configuration",
		NewValue: map[string]any{
			"users": counts.Users, "approved": counts.Approved, "requests": counts.Requests,
		},
		Source: "cli", CreatedAt: now,
	}); err != nil {
		return counts, err
	}
	return counts, nil
}

// demoVersion заводит версию пакета по имени и версии.
func (s *Service) demoVersion(ctx context.Context, manager, name, version string) (*domain.PackageVersion, error) {
	plugin, err := s.Registry.Get(manager)
	if err != nil {
		return nil, err
	}
	ref, err := registry.MakeRef(plugin, name, version)
	if err != nil {
		return nil, err
	}
	pkg, err := s.Repo.GetOrCreatePackage(ctx, ref.Manager, ref.Name, ref.DisplayName)
	if err != nil {
		return nil, err
	}
	return s.Repo.CreatePackageVersion(ctx, pkg.ID, ref.Version, ref.RawVersion)
}

// demoQuarantineRequest заводит заявку, остановленную на шаге «Карантин».
//
// Возвращает 1, если заявку завели, и 0, если она уже была: bootstrap
// запускают повторно, и вторая копия одной и той же демо-заявки сделала бы
// список заявок похожим на результат сбоя.
func (s *Service) demoQuarantineRequest(ctx context.Context, author *domain.User, now time.Time) (int, error) {
	existing, err := s.Repo.FindRequestByReason(ctx, demoRequestReason)
	if err != nil {
		return 0, err
	}
	if existing != nil {
		return 0, nil
	}

	version, err := s.demoVersion(ctx, "pypi", "httpx", "0.27.0")
	if err != nil {
		return 0, err
	}
	quarantineUntil := now.Add(11 * 24 * time.Hour)
	publishedAt := now.Add(-3 * 24 * time.Hour)
	if err := s.Repo.SetDemoVersion(ctx, version.ID, repo.DemoVersion{
		Status: "quarantined", LicenseSPDX: "BSD-3-Clause", LicenseSource: "registry",
		PublishedAt: &publishedAt, QuarantineUntil: &quarantineUntil,
	}); err != nil {
		return 0, err
	}

	role, reason := "developer", demoRequestReason
	request, err := s.Repo.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: author.ID, AuthorRole: &role, Manager: "pypi",
		Reason: &reason, Status: "quarantined", Source: "cli",
	})
	if err != nil {
		return 0, err
	}
	item, err := s.Repo.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: request.ID, PackageVersionID: version.ID,
		RequestedName: "httpx", RequestedVersion: "0.27.0",
		DependencyKind: "direct", Status: "quarantined",
	})
	if err != nil {
		return 0, err
	}
	currentStep, blocked := "quarantine", "Карантин 14 дн. не истёк"
	nextAction := "Проверка продолжится автоматически после окончания карантина."
	if err := s.Repo.UpdateRequestItemStatus(ctx, item.ID, "quarantined",
		&currentStep, &blocked, &nextAction, &now); err != nil {
		return 0, err
	}

	// Шаги заводятся все, включая непройденные: карточка заявки показывает
	// конвейер целиком, и строка «не выполнялся» — такая же часть ответа на
	// вопрос «что с моим пакетом», как и пройденная галочка.
	for order, code := range domain.StepCodes {
		var result, message string
		switch code {
		case "db_check":
			result, message = "pass", "В базе не найден, заявка принята к проверке."
		case "blacklist":
			result, message = "pass", "Совпадений с правилами blacklist нет."
		case "quarantine":
			result, message = "warn", "Версия опубликована 3 дн. назад, карантин 14 дн. не истёк."
		default:
			result, message = "skipped", "Не выполнялся: конвейер остановлен на шаге «Карантин»."
		}
		step := domain.PipelineStep{
			RequestItemID: item.ID, StepCode: code, StepOrder: order,
			Result: result, Message: &message, FinishedAt: &now,
		}
		if _, err := s.Repo.UpsertPipelineStep(ctx, step); err != nil {
			return 0, err
		}
	}
	if _, err := s.Repo.RecomputeRequestStatus(ctx, request.ID); err != nil {
		return 0, err
	}
	return 1, nil
}
