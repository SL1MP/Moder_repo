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

const userColumns = `id, subject, username, email, full_name, roles, source, is_service, is_active,
	is_superuser, must_change_password, description, password_hash, last_login_at, created_at, updated_at`

func scanUser(row scanner) (*domain.User, error) {
	var u domain.User
	var roles []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Email, &u.FullName, &roles,
		&u.Source, &u.IsService, &u.IsActive, &u.IsSuperuser, &u.MustChangePassword,
		&u.Description, &u.PasswordHash, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
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
// OIDC-пользователь сопоставляется только по неизменяемому
// subject. Локальная учётка с таким же username не связывается с SSO молча:
// это два разных способа входа и автоматическое объединение было бы захватом
// локальной учётки через внешний каталог.
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

	// Первый вход одного и того же пользователя сериализуется рекомендательной
	// блокировкой.
	//
	// Без неё два одновременных запроса не видят друг друга: строки ещё нет,
	// и `SELECT ... FOR UPDATE` внутри findUser блокировать нечего. Оба уходят
	// в INSERT, и второй падает с нарушением уникальности. ON CONFLICT в
	// insertUser от этого не спасает: у таблицы ДВА уникальных индекса
	// (username и subject), а указать в ON CONFLICT можно только один —
	// Postgres натыкается на `user_subject_key` раньше, чем доходит до
	// разбора конфликта по логину.
	//
	// Именно так это и выглядело: вход изредка отвечал ошибкой, повтор
	// помогал, воспроизвести руками не получалось. SPA при загрузке дёргает
	// несколько маршрутов сразу, и первый вход нового сотрудника — как раз
	// тот случай, когда запросы приходят одновременно.
	//
	// Блокировка транзакционная (снимается на commit/rollback сама) и взята по
	// ключу пользователя, а не на всю таблицу: разные пользователи входят
	// параллельно, как и раньше.
	if err := lockUserKey(ctx, tx, claims); err != nil {
		return nil, err
	}

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

// lockUserKey берёт рекомендательную блокировку по ключу пользователя.
//
// Ключ — subject, а если его нет, логин: именно по ним стоят уникальные
// индексы. Пространство блокировок общее на всю базу, поэтому к ключу
// добавлен префикс — иначе он мог бы совпасть с ключом другой подсистемы,
// и два несвязанных места ждали бы друг друга без всякой причины.
func lockUserKey(ctx context.Context, tx pgx.Tx, claims UserClaims) error {
	key := claims.Subject
	if key == "" {
		key = claims.Username
	}
	if key == "" {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "user:sync:"+key); err != nil {
		return fmt.Errorf("блокировка учётки %q: %w", key, err)
	}
	return nil
}

func findUser(ctx context.Context, tx pgx.Tx, claims UserClaims) (*domain.User, error) {
	if claims.Subject == "" {
		return nil, nil
	}
	user, err := scanUser(tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE source = 'oidc' AND subject = $1 FOR UPDATE`, claims.Subject))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("поиск OIDC-учётки по subject: %w", err)
	}
	return user, nil
}

func insertUser(ctx context.Context, tx pgx.Tx, claims UserClaims, now time.Time) (*domain.User, error) {
	// Keycloak подтверждает личность, но не управляет правами приложения.
	// При первом входе обычный OIDC-пользователь получает минимальную роль
	// developer. Последующие изменения ролей выполняются в web-интерфейсе;
	// роли из Keycloak не должны перезаписывать права внутри приложения.
	// Роли из локального токена оставляем для сервисных учёток.
	rolesValue := []string{"developer"}
	if claims.IsService {
		rolesValue = claims.Roles
	}
	roles, err := jsonOrEmptyList(rolesValue)
	if err != nil {
		return nil, err
	}
	// ON CONFLICT — на случай, когда два запроса одного и того же нового
	// пользователя пришли одновременно (SPA при загрузке дёргает несколько
	// маршрутов сразу). Без него один из них падал бы с нарушением
	// уникальности, и вход выглядел бы как случайная ошибка.
	user, err := scanUser(tx.QueryRow(ctx, `
		INSERT INTO "user" (subject, username, email, full_name, roles, source, is_service, is_active, last_login_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'oidc', FALSE, TRUE, $6)
		ON CONFLICT (source, subject) WHERE subject IS NOT NULL
		DO UPDATE SET email = EXCLUDED.email, updated_at = EXCLUDED.last_login_at,
		              last_login_at = EXCLUDED.last_login_at
		RETURNING `+userColumns,
		nullable(claims.Subject), claims.Username, nullable(claims.Email), nullable(claims.FullName),
		roles, now))
	if err != nil {
		return nil, fmt.Errorf("создание учётки %q: %w", claims.Username, err)
	}
	return user, nil
}

func updateUser(ctx context.Context, tx pgx.Tx, existing *domain.User, claims UserClaims, now time.Time) (*domain.User, error) {
	// Пустые claims не затирают то, что уже есть: токен сервисной учётки
	// приходит без email и имени, и затирание превратило бы карточку
	// пользователя в пустую строку после первого же захода по API.
	email := existing.Email
	if claims.Email != "" {
		email = &claims.Email
	}
	// Роли OIDC-пользователей принадлежат сервису и меняются только через
	// административный API. Keycloak здесь отвечает за аутентификацию, а не
	// за авторизацию. Сервисным учёткам роли по-прежнему можно передавать в
	// локальном токене: их выпускает сам сервис.
	rolesValue := existing.Roles
	if claims.IsService && len(claims.Roles) > 0 {
		rolesValue = claims.Roles
	}
	roles, err := jsonOrEmptyList(rolesValue)
	if err != nil {
		return nil, err
	}

	user, err := scanUser(tx.QueryRow(ctx, `
		UPDATE "user"
		SET email = $2, roles = $3::jsonb, last_login_at = $4, updated_at = $4
		WHERE id = $1
		RETURNING `+userColumns,
		existing.ID, email, roles, now))
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

// ListUsers — пользователи приложения для административного экрана.
func (r *Repo) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userColumns+` FROM "user" ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("чтение пользователей: %w", err)
	}
	defer rows.Close()

	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("чтение пользователя: %w", err)
		}
		out = append(out, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("чтение пользователей: %w", err)
	}
	return out, nil
}

// GetUserByID — пользователь административного экрана. nil, если отсутствует.
func (r *Repo) GetUserByID(ctx context.Context, id int64) (*domain.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение пользователя #%d: %w", id, err)
	}
	return u, nil
}

// CreateLocalUser создаёт обычного пользователя приложения с локальным
// паролем. Keycloak для такой учётки не требуется; роли всё равно хранятся
// в той же таблице и управляются тем же административным экраном.
func (r *Repo) CreateLocalUser(
	ctx context.Context, username, email, fullName, passwordHash string,
	roles []string, now time.Time,
) (*domain.User, error) {
	return r.CreateLocalUserWithProfile(ctx, username, email, fullName, passwordHash,
		roles, false, "", now)
}

// CreateLocalUserWithProfile создаёт локальную учётку целиком одним INSERT.
// Это важно для административного API: ответ об обязательной смене пароля не
// должен расходиться с базой из-за сбоя второго UPDATE после создания строки.
func (r *Repo) CreateLocalUserWithProfile(
	ctx context.Context, username, email, fullName, passwordHash string,
	roles []string, mustChange bool, description string, now time.Time,
) (*domain.User, error) {
	rawRoles, err := jsonOrEmptyList(roles)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(r.pool.QueryRow(ctx, `
		INSERT INTO "user" (subject, username, email, full_name, roles, source, is_service,
		                    is_active, is_superuser, must_change_password, description,
		                    password_hash, last_login_at, created_at, updated_at)
		VALUES (NULL, $1, $2, $3, $4::jsonb, 'local', FALSE, TRUE, $4::jsonb ? 'admin',
		        $5, $6, $7, NULL, $8, $8)
		RETURNING `+userColumns,
		username, nullable(email), nullable(fullName), rawRoles, mustChange, description, passwordHash, now))
	if err != nil {
		return nil, fmt.Errorf("создание локального пользователя %q: %w", username, err)
	}
	return u, nil
}

// UpdateUserAccess меняет только авторизацию. Идентичность OIDC-пользователя
// продолжает приходить из Keycloak, локального — остаётся в приложении.
func (r *Repo) UpdateUserAccess(
	ctx context.Context, id int64, roles []string, active bool, now time.Time,
) (*domain.User, error) {
	rawRoles, err := jsonOrEmptyList(roles)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(r.pool.QueryRow(ctx, `
		UPDATE "user"
		SET roles = $2::jsonb, is_superuser = $2::jsonb ? 'admin',
		    is_active = $3, updated_at = $4
		WHERE id = $1
		RETURNING `+userColumns, id, rawRoles, active, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("обновление доступа пользователя #%d: %w", id, err)
	}
	return u, nil
}

// CountActiveUsersWithRole нужен предохранителю от удаления последнего
// администратора через web.
func (r *Repo) CountActiveUsersWithRole(ctx context.Context, role string) (int, error) {
	var count int
	if err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM "user"
		WHERE is_active = TRUE AND roles ? $1`, role).Scan(&count); err != nil {
		return 0, fmt.Errorf("подсчёт пользователей с ролью %s: %w", role, err)
	}
	return count, nil
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
