package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

type OIDCSettings struct {
	Enabled       bool      `json:"enabled"`
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	PublicBaseURL string    `json:"public_base_url"`
	ButtonLabel   string    `json:"button_label"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (r *Repo) OIDCSettings(ctx context.Context) (OIDCSettings, error) {
	var value OIDCSettings
	err := r.pool.QueryRow(ctx, `
		SELECT enabled, issuer, client_id, client_secret, public_base_url, button_label, updated_at
		FROM oidc_integration WHERE id = TRUE`).Scan(
		&value.Enabled, &value.Issuer, &value.ClientID, &value.ClientSecret,
		&value.PublicBaseURL, &value.ButtonLabel, &value.UpdatedAt)
	return value, err
}

// SeedOIDCSettings переносит env-настройки только в пустую singleton-строку.
// После первого запуска источником истины становится web-настройка.
func (r *Repo) SeedOIDCSettings(ctx context.Context, value OIDCSettings) error {
	if value.Issuer == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE oidc_integration SET enabled=$1, issuer=$2, client_id=$3,
			client_secret=$4, public_base_url=$5, button_label=$6, updated_at=now()
		WHERE id=TRUE AND issuer=''`, value.Enabled, value.Issuer, value.ClientID,
		value.ClientSecret, value.PublicBaseURL, value.ButtonLabel)
	return err
}

func (r *Repo) UpdateOIDCSettings(ctx context.Context, value OIDCSettings) error {
	if value.ButtonLabel == "" {
		value.ButtonLabel = "Keycloak (SSO)"
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE oidc_integration SET enabled=$1, issuer=$2, client_id=$3,
			client_secret=CASE WHEN $4='' THEN client_secret ELSE $4 END,
			public_base_url=$5, button_label=$6, updated_at=now()
		WHERE id=TRUE`, value.Enabled, strings.TrimRight(strings.TrimSpace(value.Issuer), "/"),
		strings.TrimSpace(value.ClientID), value.ClientSecret,
		strings.TrimRight(strings.TrimSpace(value.PublicBaseURL), "/"), strings.TrimSpace(value.ButtonLabel))
	return err
}

func (r *Repo) StoreRefreshToken(ctx context.Context, userID int64, hash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_token (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
		userID, hash, expiresAt)
	return err
}

// ConsumeRefreshToken делает ротацию одноразовой: конкурентно обменять один
// refresh token более одного раза невозможно.
func (r *Repo) ConsumeRefreshToken(ctx context.Context, hash string) (int64, error) {
	var userID int64
	err := r.pool.QueryRow(ctx, `
		UPDATE refresh_token SET revoked=TRUE
		WHERE token_hash=$1 AND NOT revoked AND expires_at>now()
		RETURNING user_id`, hash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return userID, err
}

type APIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	UserID     int64      `json:"-"`
}

func (r *Repo) CreateAPIToken(ctx context.Context, userID int64, name, hash string, expiresAt *time.Time) (*APIToken, error) {
	var token APIToken
	err := r.pool.QueryRow(ctx, `
		INSERT INTO api_token (user_id,name,token_hash,expires_at) VALUES ($1,$2,$3,$4)
		RETURNING id,name,expires_at,created_at,last_used_at`, userID, name, hash, expiresAt).
		Scan(&token.ID, &token.Name, &token.ExpiresAt, &token.CreatedAt, &token.LastUsedAt)
	token.UserID = userID
	return &token, err
}

func (r *Repo) ListAPITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,name,expires_at,created_at,last_used_at
		FROM api_token WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var value APIToken
		value.UserID = userID
		if err := rows.Scan(&value.ID, &value.Name, &value.ExpiresAt, &value.CreatedAt, &value.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (r *Repo) UserByAPITokenHash(ctx context.Context, hash string) (*domain.User, *APIToken, error) {
	var token APIToken
	err := r.pool.QueryRow(ctx, `SELECT id,user_id,name,expires_at,created_at,last_used_at
		FROM api_token WHERE token_hash=$1`, hash).Scan(
		&token.ID, &token.UserID, &token.Name, &token.ExpiresAt, &token.CreatedAt, &token.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	user, err := r.GetUserByID(ctx, token.UserID)
	return user, &token, err
}

func (r *Repo) TouchAPIToken(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, `UPDATE api_token SET last_used_at=now()
		WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute')`, id)
	return err
}

func (r *Repo) DeleteAPIToken(ctx context.Context, userID, id int64) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM api_token WHERE id=$1 AND user_id=$2`, id, userID)
	return tag.RowsAffected() > 0, err
}

func (r *Repo) UpdatePassword(ctx context.Context, userID int64, hash string, mustChange bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE "user" SET password_hash=$2,
		must_change_password=$3, updated_at=now() WHERE id=$1 AND source='local'`,
		userID, hash, mustChange)
	if err == nil && tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}

func (r *Repo) UpdateUserProfile(ctx context.Context, id int64, username, email, fullName, description string,
	roles []string, active bool, passwordHash *string, mustChangePassword bool, now time.Time,
) (*domain.User, error) {
	rawRoles, err := jsonOrEmptyList(roles)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(r.pool.QueryRow(ctx, `UPDATE "user" SET username=$2,email=$3,
		full_name=$4,description=$5,roles=$6::jsonb,is_superuser=$6::jsonb ? 'admin',
		is_active=$7,
		password_hash=COALESCE($8::text,password_hash),
		must_change_password=CASE WHEN $8::text IS NULL THEN must_change_password ELSE $9 END,
		updated_at=$10 WHERE id=$1 RETURNING `+userColumns,
		id, username, nullable(email), nullable(fullName), description, rawRoles, active,
		passwordHash, mustChangePassword, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("обновление пользователя #%d: %w", id, err)
	}
	return u, nil
}

func (r *Repo) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM "user"`).Scan(&count)
	return count, err
}

const (
	loginUserLimit = 7
	loginIPLimit   = 30
)

func (r *Repo) LoginBlock(ctx context.Context, username, ip string) (time.Duration, error) {
	var until *time.Time
	err := r.pool.QueryRow(ctx, `SELECT max(locked_until) FROM login_throttle
		WHERE locked_until>now() AND ((scope='user' AND key=$1) OR (scope='ip' AND key=$2))`,
		strings.ToLower(username), ip).Scan(&until)
	if err != nil || until == nil {
		return 0, err
	}
	return time.Until(*until), nil
}

func (r *Repo) RecordLoginFailure(ctx context.Context, username, ip string) error {
	if err := r.bumpLoginThrottle(ctx, "user", strings.ToLower(username), loginUserLimit); err != nil {
		return err
	}
	return r.bumpLoginThrottle(ctx, "ip", ip, loginIPLimit)
}

func (r *Repo) bumpLoginThrottle(ctx context.Context, scope, key string, limit int) error {
	if key == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx, `INSERT INTO login_throttle(scope,key,failures) VALUES($1,$2,1)
		ON CONFLICT(scope,key) DO UPDATE SET
		failures=CASE WHEN login_throttle.first_failure_at<now()-interval '15 minutes' THEN 1 ELSE login_throttle.failures+1 END,
		first_failure_at=CASE WHEN login_throttle.first_failure_at<now()-interval '15 minutes' THEN now() ELSE login_throttle.first_failure_at END,
		locked_until=CASE WHEN login_throttle.first_failure_at>=now()-interval '15 minutes'
		AND login_throttle.failures+1 >= $3 THEN now()+LEAST(
		interval '1 minute'*power(2,(login_throttle.failures+1)/$3-1), interval '30 minutes')
		ELSE login_throttle.locked_until END, updated_at=now()`, scope, key, limit)
	return err
}

func (r *Repo) ClearLoginFailures(ctx context.Context, username, ip string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM login_throttle WHERE
		(scope='user' AND key=$1) OR (scope='ip' AND key=$2)`, strings.ToLower(username), ip)
	return err
}

// PruneLoginThrottle удаляет старые счётчики, которые уже не блокируют вход.
// Состояние хранится в Postgres, поэтому уборка одинаково работает при любом
// количестве реплик API и не требует синхронизации процесса в памяти.
func (r *Repo) PruneLoginThrottle(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM login_throttle
		WHERE updated_at < now()-interval '1 day'
		  AND (locked_until IS NULL OR locked_until < now())`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
