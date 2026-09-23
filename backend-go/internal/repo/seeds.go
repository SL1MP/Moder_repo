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

// Первичное заполнение справочников. Порт backend/app/services/seeds.py.

// ManagerSeed — строка справочника менеджеров.
type ManagerSeed struct {
	Code        string
	Title       string
	EntryFormat string
}

// SeedManagers заводит или обновляет справочник менеджеров.
//
// Источник — плагины: заголовок и формат записи объявлены там, а справочник
// в базе читает интерфейс. Две копии этих строк разъехались бы при первом же
// уточнении формулировки, и пользователь увидел бы подсказку, не совпадающую
// с тем, что на самом деле принимает разбор.
//
// UPDATE, а не DO NOTHING: формулировку подсказки как раз и уточняют, и
// обновление справочника — цель этой команды, а не побочный эффект.
func (r *Repo) SeedManagers(ctx context.Context, managers []ManagerSeed) (created int, err error) {
	for _, m := range managers {
		var inserted bool
		err := r.pool.QueryRow(ctx, `
			INSERT INTO package_manager (code, title, entry_format, enabled)
			VALUES ($1, $2, $3, TRUE)
			ON CONFLICT (code) DO UPDATE
			SET title = EXCLUDED.title, entry_format = EXCLUDED.entry_format
			RETURNING (xmax = 0)`, m.Code, m.Title, m.EntryFormat).Scan(&inserted)
		if err != nil {
			return created, fmt.Errorf("справочник менеджеров, %s: %w", m.Code, err)
		}
		if inserted {
			created++
		}
	}
	return created, nil
}

// LicenseSeed — строка справочника лицензий.
type LicenseSeed struct {
	SPDXID  string
	Name    string
	URL     string
	Allowed bool
	Notes   string
}

// SeedLicenses заводит справочник лицензий в базе по файлу политики.
//
// Зачем он в базе, если решение принимается по файлу: файл — источник правды
// для конвейера, а таблица нужна выпадающему списку в карточке пакета и
// внешнему ключу у заявления лицензии. Расхождение между ними не опасно
// (вердикт выносит файл), но список, в котором нет лицензии из файла, мешает
// разработчику её заявить.
func (r *Repo) SeedLicenses(ctx context.Context, licenses []LicenseSeed) (created int, err error) {
	for _, l := range licenses {
		var inserted bool
		err := r.pool.QueryRow(ctx, `
			INSERT INTO license (spdx_id, name, url, allowed, notes)
			VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''))
			ON CONFLICT (spdx_id) DO UPDATE
			SET name = EXCLUDED.name, url = EXCLUDED.url,
			    allowed = EXCLUDED.allowed, notes = EXCLUDED.notes
			RETURNING (xmax = 0)`,
			l.SPDXID, l.Name, l.URL, l.Allowed, l.Notes).Scan(&inserted)
		if err != nil {
			return created, fmt.Errorf("справочник лицензий, %s: %w", l.SPDXID, err)
		}
		if inserted {
			created++
		}
	}
	return created, nil
}

// UpsertServiceAccount заводит или обновляет сервисную учётную запись.
//
// Отдельно от SyncUser: та синхронизирует человека по claim'ам токена OIDC, а
// здесь заводится учётка для CI, у которой ни субъекта в каталоге, ни почты
// нет — только логин, пароль и роли.
func (r *Repo) UpsertServiceAccount(
	ctx context.Context, username string, roles []string, passwordHash string, now time.Time,
) (*domain.User, error) {
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO "user" (username, full_name, roles, is_service, is_active,
		                    password_hash, created_at, updated_at)
		VALUES ($1, $1, $2::jsonb, TRUE, TRUE, $3, $4, $4)
		ON CONFLICT (username) DO UPDATE
		SET roles = EXCLUDED.roles, is_service = TRUE, is_active = TRUE,
		    password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at
		RETURNING id, subject, username, email, full_name, roles, is_service, is_active,
		          password_hash, last_login_at, created_at, updated_at`,
		username, rolesJSON, passwordHash, now)

	var u domain.User
	var rawRoles []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Email, &u.FullName, &rawRoles,
		&u.IsService, &u.IsActive, &u.PasswordHash, &u.LastLoginAt,
		&u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, fmt.Errorf("сервисная учётная запись %q: %w", username, err)
	}
	if err := json.Unmarshal(rawRoles, &u.Roles); err != nil {
		return nil, fmt.Errorf("роли учётной записи %q не разобраны: %w", username, err)
	}
	return &u, nil
}

// MarkVersionImported переводит версию в «одобрена» по импорту существующего
// списка пакетов.
//
// Отдельный метод, а не UpdatePackageVersionStatus: импорт обязан проставить
// ещё и approved_at, иначе пакет выглядит одобренным без даты одобрения — и
// перепроверка по новой базе уязвимостей, которая отбирает пакеты по этой
// дате, такой пакет никогда не возьмёт.
//
// license_source сохраняется, если уже заполнен: версия могла попасть в базу
// заявкой, в которой лицензию прочитали из реестра, и затирать этот источник
// словом «вручную» значило бы потерять знание о том, откуда лицензия взялась.
func (r *Repo) MarkVersionImported(ctx context.Context, id int64, reason string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version
		SET status = 'approved',
		    approved_at = $2,
		    status_reason = $3,
		    license_source = COALESCE(NULLIF(license_source, ''), 'manual'),
		    updated_at = now()
		WHERE id = $1`, id, now, reason)
	if err != nil {
		return fmt.Errorf("импорт версии #%d: %w", id, err)
	}
	return nil
}

// DemoUser — учётка демо-стенда.
type DemoUser struct {
	Username string
	FullName string
	Email    string
	Roles    []string
}

// UpsertDemoUser заводит или обновляет демо-учётку.
//
// passwordHash пустой — пароль не трогаем: стенд мог быть поднят с паролем, и
// повторный bootstrap без --service-password не имеет права молча отобрать
// вход у того, кто им уже пользуется.
func (r *Repo) UpsertDemoUser(ctx context.Context, u DemoUser, passwordHash string) (*domain.User, error) {
	rolesJSON, err := json.Marshal(u.Roles)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO "user" (username, full_name, email, roles, is_service, is_active,
		                    password_hash)
		VALUES ($1, $2, NULLIF($3, ''), $4::jsonb, $5, TRUE, NULLIF($6, ''))
		ON CONFLICT (username) DO UPDATE
		SET full_name = EXCLUDED.full_name, email = EXCLUDED.email,
		    roles = EXCLUDED.roles, is_active = TRUE,
		    is_service = "user".is_service OR EXCLUDED.is_service,
		    password_hash = COALESCE(EXCLUDED.password_hash, "user".password_hash),
		    updated_at = now()
		RETURNING id, subject, username, email, full_name, roles, is_service, is_active,
		          password_hash, last_login_at, created_at, updated_at`,
		u.Username, u.FullName, u.Email, rolesJSON, passwordHash != "", passwordHash)

	var user domain.User
	var rawRoles []byte
	if err := row.Scan(&user.ID, &user.Subject, &user.Username, &user.Email, &user.FullName,
		&rawRoles, &user.IsService, &user.IsActive, &user.PasswordHash, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, fmt.Errorf("демо-учётка %q: %w", u.Username, err)
	}
	if err := json.Unmarshal(rawRoles, &user.Roles); err != nil {
		return nil, fmt.Errorf("роли демо-учётки %q не разобраны: %w", u.Username, err)
	}
	return &user, nil
}

// DemoVersion — поля версии, которые проставляет демо-стенд.
type DemoVersion struct {
	Status          string
	LicenseSPDX     string
	LicenseSource   string
	PublishedAt     *time.Time
	ApprovedAt      *time.Time
	QuarantineUntil *time.Time
	MaxVulnScore    *float64
}

// SetDemoVersion проставляет версии состояние демо-стенда одним UPDATE.
//
// Отдельно от точечных сеттеров конвейера намеренно: те повторяют переходы
// настоящих шагов и не имеют права выставлять «одобрено» вместе с датой
// публикации задним числом. Демо-данные — это как раз подделка истории, и
// делать её надо там, где видно, что это подделка.
func (r *Repo) SetDemoVersion(ctx context.Context, id int64, v DemoVersion) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET
			status = $2,
			license_spdx = COALESCE(NULLIF($3, ''), license_spdx),
			license_source = COALESCE(NULLIF($4, ''), license_source),
			published_at = COALESCE($5, published_at),
			approved_at = COALESCE($6, approved_at),
			quarantine_until = $7,
			max_vuln_score = COALESCE($8, max_vuln_score),
			updated_at = now()
		WHERE id = $1`,
		id, v.Status, v.LicenseSPDX, v.LicenseSource,
		v.PublishedAt, v.ApprovedAt, v.QuarantineUntil, v.MaxVulnScore)
	if err != nil {
		return fmt.Errorf("демо-версия #%d: %w", id, err)
	}
	return nil
}

// FindRequestByReason — заявка с такой причиной. nil, если её нет.
//
// Нужен ровно одному вызывающему — демо-данным: повторный bootstrap обязан
// узнать свою же заявку и не заводить вторую. Искать по причине, а не по
// пакету, потому что пакет в заявке может смениться, а метка «демо» — нет.
func (r *Repo) FindRequestByReason(ctx context.Context, reason string) (*domain.ModerationRequest, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`SELECT id FROM moderation_request WHERE reason = $1 ORDER BY id LIMIT 1`, reason).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("поиск заявки по причине: %w", err)
	}
	return r.GetModerationRequest(ctx, id)
}

// ManagerRow и LicenseRow — строки справочников, как они лежат в базе.
type ManagerRow struct {
	Code        string
	Title       string
	EntryFormat string
	Enabled     bool
}

type LicenseRow struct {
	SPDXID  string
	Name    string
	Allowed bool
}

// ListManagers — справочник менеджеров из базы.
//
// Именно из базы, а не из плагинов: список плагинов сервис знает и так, а
// вопрос, на который отвечает эта выборка, — «что увидит интерфейс, читающий
// таблицу». Разойтись эти два списка могут ровно потому, что заполняет
// таблицу отдельная команда, которую можно забыть запустить.
func (r *Repo) ListManagers(ctx context.Context) ([]ManagerRow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT code, title, entry_format, enabled FROM package_manager ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("чтение справочника менеджеров: %w", err)
	}
	defer rows.Close()
	var out []ManagerRow
	for rows.Next() {
		var m ManagerRow
		if err := rows.Scan(&m.Code, &m.Title, &m.EntryFormat, &m.Enabled); err != nil {
			return nil, fmt.Errorf("чтение справочника менеджеров: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListLicenses — справочник лицензий из базы (для автодополнения и проверок).
func (r *Repo) ListLicenses(ctx context.Context) ([]LicenseRow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT spdx_id, COALESCE(name, ''), allowed FROM license ORDER BY spdx_id`)
	if err != nil {
		return nil, fmt.Errorf("чтение справочника лицензий: %w", err)
	}
	defer rows.Close()
	var out []LicenseRow
	for rows.Next() {
		var l LicenseRow
		if err := rows.Scan(&l.SPDXID, &l.Name, &l.Allowed); err != nil {
			return nil, fmt.Errorf("чтение справочника лицензий: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
