package repo

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"moderation/internal/domain"
)

// Синхронизация учётки идёт на КАЖДОМ закрытом запросе, поэтому проверяется
// на настоящем Postgres: половина её поведения — это ограничения схемы
// (уникальность логина и subject, NOT NULL на roles), и на моке она
// «работает» ровно до первого прода.

func TestSyncUserCreatesAndUpdates(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	username := uniqueName(t)
	claims := UserClaims{
		Subject: username + "-sub", Username: username,
		Email: username + "@example.com", FullName: "Иван Иванов",
		Roles: []string{"legal"},
	}

	created, err := r.SyncUser(ctx, claims, now)
	if err != nil {
		t.Fatalf("первый вход: %v", err)
	}
	if created.ID == 0 || created.Username != username {
		t.Fatalf("учётка не заведена: %+v", created)
	}
	if !created.IsActive {
		t.Fatal("новая учётка должна быть активной")
	}
	if len(created.Roles) != 1 || created.Roles[0] != "legal" {
		t.Fatalf("роли: %v", created.Roles)
	}
	if created.LastLoginAt == nil {
		t.Fatal("время входа должно проставляться")
	}

	// Повторный вход с новой ролью: роль меняется, учётка та же.
	claims.Roles = []string{"admin", "devsecops"}
	updated, err := r.SyncUser(ctx, claims, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("второй вход: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("должна обновляться та же учётка: было %d, стало %d", created.ID, updated.ID)
	}
	if strings.Join(updated.Roles, ",") != "admin,devsecops" {
		t.Fatalf("роли из каталога должны применяться: %v", updated.Roles)
	}
}

// Каталог не прислал ни одной роли — это почти всегда сбой маппера групп в
// Keycloak, а не разжалование. Тихо снять права со всех пользователей
// сервиса из-за такого сбоя нельзя.
func TestSyncUserKeepsRolesWhenClaimsEmpty(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC()

	username := uniqueName(t)
	claims := UserClaims{Subject: username + "-sub", Username: username, Roles: []string{"devsecops"}}
	if _, err := r.SyncUser(ctx, claims, now); err != nil {
		t.Fatalf("первый вход: %v", err)
	}

	claims.Roles = nil
	after, err := r.SyncUser(ctx, claims, now)
	if err != nil {
		t.Fatalf("вход без ролей: %v", err)
	}
	if len(after.Roles) != 1 || after.Roles[0] != "devsecops" {
		t.Fatalf("роли не должны сбрасываться пустыми claims: %v", after.Roles)
	}
}

// Пустые email и имя не затирают заполненные: токен сервисной учётки
// приходит без них.
func TestSyncUserKeepsProfileWhenClaimsEmpty(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC()

	username := uniqueName(t)
	full := "Иван Иванов"
	claims := UserClaims{
		Subject: username + "-sub", Username: username,
		Email: username + "@example.com", FullName: full, Roles: []string{"developer"},
	}
	if _, err := r.SyncUser(ctx, claims, now); err != nil {
		t.Fatalf("первый вход: %v", err)
	}

	claims.Email, claims.FullName = "", ""
	after, err := r.SyncUser(ctx, claims, now)
	if err != nil {
		t.Fatalf("второй вход: %v", err)
	}
	if after.Email == nil || after.FullName == nil || *after.FullName != full {
		t.Fatalf("профиль не должен затираться: %+v", after)
	}
}

// Учётку, заведённую локально (без subject), первый вход через SSO обязан
// привязать к каталогу — иначе получится вторая учётка с тем же логином, и
// уникальность логина этого просто не даст: вход сломается.
func TestSyncUserAttachesSubjectToLocalAccount(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC()

	username := uniqueName(t)
	local, err := r.GetOrCreateUser(ctx, username, username)
	if err != nil {
		t.Fatalf("локальная учётка: %v", err)
	}
	if local.Subject != nil {
		t.Fatalf("у локальной учётки не должно быть subject: %v", *local.Subject)
	}

	linked, err := r.SyncUser(ctx, UserClaims{
		Subject: username + "-sub", Username: username, Roles: []string{"legal"},
	}, now)
	if err != nil {
		t.Fatalf("вход через SSO: %v", err)
	}
	if linked.ID != local.ID {
		t.Fatalf("должна быть та же учётка: было %d, стало %d", local.ID, linked.ID)
	}
	if linked.Subject == nil || *linked.Subject != username+"-sub" {
		t.Fatalf("subject должен привязаться: %+v", linked.Subject)
	}
}

// Логин в каталоге переименовали: учётка ищется по subject, а логин остаётся
// прежним — на него ссылаются записи аудита и подписи решений.
func TestSyncUserFindsRenamedAccountBySubject(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC()

	username := uniqueName(t)
	subject := username + "-sub"
	first, err := r.SyncUser(ctx, UserClaims{Subject: subject, Username: username, Roles: []string{"legal"}}, now)
	if err != nil {
		t.Fatalf("первый вход: %v", err)
	}

	renamed, err := r.SyncUser(ctx, UserClaims{
		Subject: subject, Username: username + "-новый", Roles: []string{"legal"},
	}, now)
	if err != nil {
		t.Fatalf("вход после переименования: %v", err)
	}
	if renamed.ID != first.ID {
		t.Fatalf("учётка должна найтись по subject: было %d, стало %d", first.ID, renamed.ID)
	}
	if renamed.Username != username {
		t.Fatalf("логин не должен меняться задним числом: %q", renamed.Username)
	}
}

// SPA при загрузке дёргает несколько закрытых маршрутов сразу, и для нового
// пользователя они приходят одновременно. Без обработки гонки один из
// запросов падает с нарушением уникальности — вход выглядит как случайная
// ошибка «то работает, то нет».
//
// Тест повторяет столкновение много раз и с большим числом горутин НЕ ради
// солидности. В прежнем виде (шесть горутин, один раунд) он ловил поломку
// примерно раз в двадцать прогонов: этого хватило, чтобы она однажды всплыла
// в общем прогоне, но не хватило бы, чтобы её найти. Проверено: со снятой
// блокировкой в SyncUser текущий вариант падает на 10 раундах из 60, прежний
// не падал ни разу за 15 прогонов подряд.
func TestSyncUserConcurrentFirstLogin(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()

	// parallel больше числа ядер намеренно: столкновение нужно в момент
	// ВСТАВКИ, а не в момент планирования горутин.
	const parallel = 16
	const rounds = 20

	for round := 0; round < rounds; round++ {
		username := fmt.Sprintf("%s-%d", uniqueName(t), round)
		claims := UserClaims{
			Subject: username + "-sub", Username: username, Roles: []string{"developer"},
		}
		now := time.Now().UTC()

		// Старт по общему сигналу, а не «как запустятся»: без барьера горутины
		// расходятся во времени и в окно вставки не попадают.
		var ready, wg sync.WaitGroup
		start := make(chan struct{})
		ids := make([]int64, parallel)
		errs := make([]error, parallel)
		ready.Add(parallel)
		wg.Add(parallel)
		for i := 0; i < parallel; i++ {
			go func(i int) {
				defer wg.Done()
				ready.Done()
				<-start
				user, err := r.SyncUser(ctx, claims, now)
				errs[i] = err
				if user != nil {
					ids[i] = user.ID
				}
			}(i)
		}
		ready.Wait()
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("раунд %d, параллельный вход %d: %v", round, i, err)
			}
		}
		// Одна учётка на всех, а не просто отсутствие ошибки: шесть успешных
		// запросов, создавших шесть разных строк, — это тоже поломка, просто
		// тихая.
		for i, id := range ids {
			if id != ids[0] {
				t.Fatalf("раунд %d: все запросы должны получить одну учётку: %d != %d (запрос %d)",
					round, id, ids[0], i)
			}
		}
	}
}

func TestInsertAuditLog(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()
	now := time.Now().UTC()

	username := uniqueName(t)
	user, err := r.SyncUser(ctx, UserClaims{
		Subject: username + "-sub", Username: username, Roles: []string{"devsecops"},
	}, now)
	if err != nil {
		t.Fatalf("учётка: %v", err)
	}

	role := "devsecops"
	rid := "req-" + username
	entityID := "42"
	if err := r.InsertAuditLog(ctx, domainAuditLog(user.ID, username, role, rid, entityID, now)); err != nil {
		t.Fatalf("запись аудита: %v", err)
	}

	var action, actorName string
	var newValue []byte
	err = r.pool.QueryRow(ctx,
		`SELECT action, actor_name, new_value FROM audit_log WHERE request_id = $1`, rid).
		Scan(&action, &actorName, &newValue)
	if err != nil {
		t.Fatalf("чтение аудита: %v", err)
	}
	if action != "local_login" || actorName != username {
		t.Fatalf("запись аудита: %q %q", action, actorName)
	}
	if !strings.Contains(string(newValue), "ok") {
		t.Fatalf("new_value должен сохраняться как JSON: %s", newValue)
	}
}

// Неудачный вход пишется в аудит без учётки: пользователя может не
// существовать вовсе, а запись о попытке подбора терять нельзя.
func TestInsertAuditLogWithoutActor(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := context.Background()

	rid := "req-" + uniqueName(t)
	entry := domainAuditLog(0, "кого-нет", "", rid, "кого-нет", time.Now().UTC())
	entry.ActorID = nil
	entry.ActorRole = nil
	entry.Action = "local_login_failed"
	entry.NewValue = map[string]any{"result": "denied"}
	if err := r.InsertAuditLog(ctx, entry); err != nil {
		t.Fatalf("запись аудита без учётки: %v", err)
	}
}

func uniqueName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("тест-%s-%d", strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")), time.Now().UnixNano())
}

func domainAuditLog(actorID int64, name, role, requestID, entityID string, now time.Time) domain.AuditLog {
	entry := domain.AuditLog{
		ActorName:  name,
		Action:     "local_login",
		EntityType: "user",
		EntityID:   &entityID,
		NewValue:   map[string]any{"result": "ok"},
		Source:     "api",
		RequestID:  &requestID,
		CreatedAt:  now,
	}
	if actorID != 0 {
		entry.ActorID = &actorID
	}
	if role != "" {
		entry.ActorRole = &role
	}
	return entry
}
