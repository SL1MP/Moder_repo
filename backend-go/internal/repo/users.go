package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

const userColumns = `id, subject, username, email, full_name, roles, is_service, is_active,
	password_hash, last_login_at, created_at, updated_at`

func scanUser(row scanner) (*domain.User, error) {
	var u domain.User
	var roles []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Email, &u.FullName, &roles,
		&u.IsService, &u.IsActive, &u.PasswordHash, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	if err := unmarshalInto(roles, &u.Roles); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByUsername — учётка по логину. nil, если такой нет.
func (r *Repo) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	user, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE username = $1`, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение учётки %q: %w", username, err)
	}
	return user, nil
}

// SyncUser заводит или обновляет учётку по claims токена. Порт
// security.sync_user.
//
// Ищем сначала по subject, потом по логину: subject неизменен, а логин в
// каталоге могут переименовать. Найденной по логину учётке subject
// проставляется — так учётка, заведённая локально (или прошлой версией без
// OIDC), привязывается к каталогу без ручного вмешательства.
//
// Логин у уже существующей учётки НЕ меняется, даже если в каталоге он стал
// другим: на него ссылаются записи аудита и подписи решений, и переименование
// задним числом сделало бы историю нечитаемой. Это поведение python-версии,
// и менять его здесь, посреди переноса, нельзя — обе версии пишут в одну базу.
func (r *Repo) SyncUser(ctx context.Context, claims UserClaims, now time.Time) (*domain.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("начало транзакции синхронизации учётки: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := findUser(ctx, tx, claims)
	if err != nil {
		return nil, err
	}

	var user *domain.User
	if existing == nil {
		user, err = insertUser(ctx, tx, claims, now)
	} else {
		user, err = updateUser(ctx, tx, existing, claims, now)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("фиксация синхронизации учётки: %w", err)
	}
	return user, nil
}

// UserClaims — то, что репозиторию нужно знать о токене. Своя структура, а не
// auth.Claims: репозиторий не должен зависеть от способа аутентификации.
type UserClaims struct {
	Subject   string
	Username  string
	Email     string
	FullName  string
	Roles     []string
	IsService bool
}

func findUser(ctx context.Context, tx pgx.Tx, claims UserClaims) (*domain.User, error) {
	if claims.Subject != "" {
		user, err := scanUser(tx.QueryRow(ctx,
			`SELECT `+userColumns+` FROM "user" WHERE subject = $1 FOR UPDATE`, claims.Subject))
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("поиск учётки по subject: %w", err)
		}
	}
	user, err := scanUser(tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE username = $1 FOR UPDATE`, claims.Username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("поиск учётки по логину: %w", err)
	}
	return user, nil
}

func insertUser(ctx context.Context, tx pgx.Tx, claims UserClaims, now time.Time) (*domain.User, error) {
	roles, err := jsonOrEmptyList(claims.Roles)
	if err != nil {
		return nil, err
	}
	// ON CONFLICT — на случай, когда два запроса одного и того же нового
	// пользователя пришли одновременно (SPA при загрузке дёргает несколько
	// маршрутов сразу). Без него один из них падал бы с нарушением
	// уникальности, и вход выглядел бы как случайная ошибка.
	user, err := scanUser(tx.QueryRow(ctx, `
		INSERT INTO "user" (subject, username, email, full_name, roles, is_service, is_active, last_login_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, TRUE, $7)
		ON CONFLICT (username) DO UPDATE SET last_login_at = EXCLUDED.last_login_at
		RETURNING `+userColumns,
		nullable(claims.Subject), claims.Username, nullable(claims.Email), nullable(claims.FullName),
		roles, claims.IsService, now))
	if err != nil {
		return nil, fmt.Errorf("создание учётки %q: %w", claims.Username, err)
	}
	return user, nil
}

func updateUser(ctx context.Context, tx pgx.Tx, existing *domain.User, claims UserClaims, now time.Time) (*domain.User, error) {
	// Пустые claims не затирают то, что уже есть: токен сервисной учётки
	// приходит без email и имени, и затирание превратило бы карточку
	// пользователя в пустую строку после первого же захода по API.
	subject := existing.Subject
	if subject == nil || *subject == "" {
		subject = nullablePtr(claims.Subject)
	}
	email := existing.Email
	if claims.Email != "" {
		email = &claims.Email
	}
	fullName := existing.FullName
	if claims.FullName != "" {
		fullName = &claims.FullName
	}
	// Роли берутся из каталога только если он их прислал. Если каталог не
	// прислал ни одной, а в базе они есть, — оставляем как есть: иначе
	// временный сбой маппера групп в Keycloak молча разжаловал бы всех
	// пользователей сервиса.
	rolesValue := existing.Roles
	if len(claims.Roles) > 0 {
		rolesValue = claims.Roles
	}
	roles, err := jsonOrEmptyList(rolesValue)
	if err != nil {
		return nil, err
	}

	user, err := scanUser(tx.QueryRow(ctx, `
		UPDATE "user"
		SET subject = $2, email = $3, full_name = $4, roles = $5::jsonb,
		    last_login_at = $6, updated_at = $6
		WHERE id = $1
		RETURNING `+userColumns,
		existing.ID, subject, email, fullName, roles, now))
	if err != nil {
		return nil, fmt.Errorf("обновление учётки %q: %w", existing.Username, err)
	}
	return user, nil
}

// InsertAuditLog пишет запись аудита. Порт services.audit.record.
func (r *Repo) InsertAuditLog(ctx context.Context, entry domain.AuditLog) error {
	oldValue, err := jsonOrNull(entry.OldValue)
	if err != nil {
		return err
	}
	newValue, err := jsonOrNull(entry.NewValue)
	if err != nil {
		return err
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_id, actor_name, actor_role, action, entity_type, entity_id,
		                       old_value, new_value, source, request_id, ip, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13)`,
		entry.ActorID, entry.ActorName, entry.ActorRole, entry.Action, entry.EntityType, entry.EntityID,
		oldValue, newValue, entry.Source, entry.RequestID, entry.IP, entry.Comment, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("запись аудита %q: %w", entry.Action, err)
	}
	return nil
}

// jsonOrEmptyList — роли всегда пишутся списком, пустой список как `[]`, а не
// NULL: колонка roles объявлена NOT NULL, и python-версия кладёт туда
// default=list.
func jsonOrEmptyList(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("сборка списка ролей: %w", err)
	}
	return string(raw), nil
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullablePtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// TouchLastLogin отмечает время входа. Отдельно от SyncUser: локальный вход
// ничего не узнаёт о пользователе из каталога, и полная синхронизация там
// означала бы переписывание ролей теми же значениями безо всякой нужды.
func (r *Repo) TouchLastLogin(ctx context.Context, userID int64, now time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE "user" SET last_login_at = $2, updated_at = $2 WHERE id = $1`, userID, now)
	if err != nil {
		return fmt.Errorf("отметка времени входа: %w", err)
	}
	return nil
}

// SetGitlabTokens сохраняет или убирает подключение GitLab.
//
// Одним UPDATE, а не четырьмя: подключение — это состояние целиком, и
// промежуточное состояние «токен есть, срок нет» ничего не значит. Отключение
// передаёт nil во всех полях и попадает в ту же ветку.
//
// Токены приходят уже зашифрованными: шифрование — дело того, кто знает ключ,
// а репозиторий не должен уметь читать то, что хранит.
func (r *Repo) SetGitlabTokens(
	ctx context.Context, userID int64,
	access, refresh *string, expiresAt *time.Time, username *string,
) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE "user"
		SET gitlab_access_token_enc = $2,
		    gitlab_refresh_token_enc = $3,
		    gitlab_token_expires_at = $4,
		    gitlab_username = $5,
		    updated_at = now()
		WHERE id = $1`, userID, access, refresh, expiresAt, username)
	if err != nil {
		return fmt.Errorf("сохранение подключения GitLab: %w", err)
	}
	return nil
}
