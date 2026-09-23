package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

// Операции, нужные шагам конвейера 4–8: артефакты, находки сканеров,
// уязвимости, версии снапшота OSV и отчёты о сканировании.

// GetOrCreateArtifact — артефакт версии пакета по имени файла. Порт
// _get_or_create_artifact из steps.py: повторный прогон шага скачивания не
// должен плодить строки на ту же версию.
func (r *Repo) GetOrCreateArtifact(ctx context.Context, packageVersionID int64, filename string) (*domain.Artifact, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO artifact (package_version_id, filename, status)
		VALUES ($1, $2, 'downloaded')
		ON CONFLICT ON CONSTRAINT uq_artifact_package_version_id_filename DO UPDATE SET filename = EXCLUDED.filename
		RETURNING id, package_version_id, filename, source_url, size_bytes, sha256,
		          declared_checksum, checksum_algo, staging_repo, staging_path, staged_at,
		          staging_cleared_at, nexus_url, published_at, status
	`, packageVersionID, filename)
	return scanArtifact(row)
}

// CurrentArtifact — артефакт, с которым работают шаги сканирования и
// публикации. Порт _current_artifact: берётся самый ранний из тех, у кого есть
// ключ в хранилище или адрес в артефактори, причём неудалённые предпочтительнее.
func (r *Repo) CurrentArtifact(ctx context.Context, packageVersionID int64) (*domain.Artifact, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, package_version_id, filename, source_url, size_bytes, sha256,
		       declared_checksum, checksum_algo, staging_repo, staging_path, staged_at,
		       staging_cleared_at, nexus_url, published_at, status
		FROM artifact
		WHERE package_version_id = $1 AND (staging_path IS NOT NULL OR nexus_url IS NOT NULL)
		ORDER BY (staging_cleared_at IS NOT NULL), id
		LIMIT 1
	`, packageVersionID)
	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return artifact, nil
}

// UpdateArtifactDownloaded — фиксирует результат шага скачивания.
func (r *Repo) UpdateArtifactDownloaded(ctx context.Context, a *domain.Artifact) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE artifact SET
			source_url = $2, size_bytes = $3, sha256 = $4, declared_checksum = $5,
			checksum_algo = $6, staging_repo = $7, staging_path = $8, staged_at = $9,
			staging_cleared_at = NULL, status = 'downloaded'
		WHERE id = $1
	`, a.ID, a.SourceURL, a.SizeBytes, a.SHA256, a.DeclaredChecksum,
		a.ChecksumAlgo, a.StagingRepo, a.StagingPath, a.StagedAt)
	if err != nil {
		return fmt.Errorf("обновление артефакта после скачивания: %w", err)
	}
	return nil
}

// SetArtifactStatus — точечная смена статуса (например, downloaded -> scanned).
func (r *Repo) SetArtifactStatus(ctx context.Context, id int64, status string) error {
	if _, err := r.pool.Exec(ctx, `UPDATE artifact SET status = $2 WHERE id = $1`, id, status); err != nil {
		return fmt.Errorf("смена статуса артефакта: %w", err)
	}
	return nil
}

// MarkArtifactPublished — адрес в артефактори и время публикации.
func (r *Repo) MarkArtifactPublished(ctx context.Context, id int64, url string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE artifact SET nexus_url = $2, published_at = $3, status = 'published' WHERE id = $1
	`, id, url, at)
	if err != nil {
		return fmt.Errorf("отметка артефакта опубликованным: %w", err)
	}
	return nil
}

// MarkArtifactPurged — объект удалён из карантинной зоны. keepStatus=true
// оставляет статус published: объект удаляется и после успешной публикации,
// и это не «purged», а штатная уборка.
func (r *Repo) MarkArtifactPurged(ctx context.Context, id int64, at time.Time, keepStatus bool) error {
	query := `UPDATE artifact SET staging_cleared_at = $2, status = 'purged' WHERE id = $1`
	if keepStatus {
		query = `UPDATE artifact SET staging_cleared_at = $2 WHERE id = $1`
	}
	if _, err := r.pool.Exec(ctx, query, id, at); err != nil {
		return fmt.Errorf("отметка объекта удалённым из хранилища: %w", err)
	}
	return nil
}

// ListArtifacts — все артефакты версии пакета (нужно при отклонении: вычистить
// все объекты, а не только текущий).
func (r *Repo) ListArtifacts(ctx context.Context, packageVersionID int64) ([]domain.Artifact, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, filename, source_url, size_bytes, sha256,
		       declared_checksum, checksum_algo, staging_repo, staging_path, staged_at,
		       staging_cleared_at, nexus_url, published_at, status
		FROM artifact WHERE package_version_id = $1 ORDER BY id
	`, packageVersionID)
	if err != nil {
		return nil, fmt.Errorf("чтение артефактов версии пакета: %w", err)
	}
	defer rows.Close()

	var out []domain.Artifact
	for rows.Next() {
		artifact, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *artifact)
	}
	return out, rows.Err()
}

func scanArtifact(row scanner) (*domain.Artifact, error) {
	var a domain.Artifact
	if err := row.Scan(
		&a.ID, &a.PackageVersionID, &a.Filename, &a.SourceURL, &a.SizeBytes, &a.SHA256,
		&a.DeclaredChecksum, &a.ChecksumAlgo, &a.StagingRepo, &a.StagingPath, &a.StagedAt,
		&a.StagingClearedAt, &a.NexusURL, &a.PublishedAt, &a.Status,
	); err != nil {
		return nil, fmt.Errorf("чтение artifact: %w", err)
	}
	return &a, nil
}

// --------------------------------------------------------------------------- находки сканеров

// ReplaceCodeFindings перезаписывает находки одного сканера для версии пакета.
//
// Именно перезаписывает, а не дополняет: находки отвечают на вопрос «что
// показать в карточке сейчас», и повторный прогон обязан вытеснить прошлый
// результат, иначе исправленный пакет остался бы с находками навсегда.
// История прогонов живёт в scan_report.
func (r *Repo) ReplaceCodeFindings(ctx context.Context, packageVersionID int64, scannerName string, findings []domain.CodeFinding) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало транзакции для находок сканера: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // откат после успешного Commit — no-op

	if _, err := tx.Exec(ctx,
		`DELETE FROM code_finding WHERE package_version_id = $1 AND scanner = $2`,
		packageVersionID, scannerName); err != nil {
		return fmt.Errorf("удаление прошлых находок сканера: %w", err)
	}

	now := time.Now().UTC()
	for i := range findings {
		f := findings[i]
		if _, err := tx.Exec(ctx, `
			INSERT INTO code_finding
				(package_version_id, scanner, rule_id, severity, message, file_path, line, matched, detected_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, packageVersionID, f.Scanner, f.RuleID, f.Severity, f.Message,
			f.FilePath, f.Line, f.Matched, now); err != nil {
			return fmt.Errorf("сохранение находки сканера: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация находок сканера: %w", err)
	}
	return nil
}

// ListCodeFindings — находки версии пакета, самые серьёзные первыми.
func (r *Repo) ListCodeFindings(ctx context.Context, packageVersionID int64) ([]domain.CodeFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, scanner, rule_id, severity, message,
		       file_path, line, matched, detected_at
		FROM code_finding WHERE package_version_id = $1
		ORDER BY
			CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
			              WHEN 'low' THEN 3 ELSE 4 END,
			file_path, line, id
	`, packageVersionID)
	if err != nil {
		return nil, fmt.Errorf("чтение находок сканеров: %w", err)
	}
	defer rows.Close()

	var out []domain.CodeFinding
	for rows.Next() {
		var f domain.CodeFinding
		if err := rows.Scan(&f.ID, &f.PackageVersionID, &f.Scanner, &f.RuleID, &f.Severity,
			&f.Message, &f.FilePath, &f.Line, &f.Matched, &f.DetectedAt); err != nil {
			return nil, fmt.Errorf("чтение code_finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// --------------------------------------------------------------------------- уязвимости

// UpsertVulnerabilities — находки шага проверки уязвимостей. В отличие от
// находок сканеров содержимого, здесь именно upsert по (версия, external_id):
// уязвимость, найденная прошлым прогоном, остаётся связанной с версией, даже
// если свежий снапшот её пока не видит.
func (r *Repo) UpsertVulnerabilities(ctx context.Context, packageVersionID int64, findings []domain.Vulnerability, indexVersionID *int64) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало транзакции для уязвимостей: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // откат после успешного Commit — no-op

	now := time.Now().UTC()
	for i := range findings {
		v := findings[i]
		aliases, err := jsonOrNull(v.Aliases)
		if err != nil {
			return err
		}
		ranges, err := jsonOrNull(v.AffectedRanges)
		if err != nil {
			return err
		}
		fixed, err := jsonOrNull(v.FixedVersions)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vulnerability
				(package_version_id, external_id, aliases, summary, cvss_vector, cvss_score,
				 score, severity, url, affected_ranges, fixed_versions, vuln_index_version_id, detected_at)
			VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13)
			ON CONFLICT ON CONSTRAINT uq_vulnerability_package_version_id DO UPDATE SET
				aliases = EXCLUDED.aliases, summary = EXCLUDED.summary,
				cvss_vector = EXCLUDED.cvss_vector, cvss_score = EXCLUDED.cvss_score,
				score = EXCLUDED.score, severity = EXCLUDED.severity, url = EXCLUDED.url,
				affected_ranges = EXCLUDED.affected_ranges, fixed_versions = EXCLUDED.fixed_versions,
				vuln_index_version_id = EXCLUDED.vuln_index_version_id, detected_at = EXCLUDED.detected_at
		`, packageVersionID, v.ExternalID, aliases, v.Summary, v.CVSSVector, v.CVSSScore,
			v.Score, v.Severity, v.URL, ranges, fixed, indexVersionID, now); err != nil {
			return fmt.Errorf("сохранение уязвимости %s: %w", v.ExternalID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация уязвимостей: %w", err)
	}
	return nil
}

// UpsertVulnIndexVersion — версия снапшота OSV, по которой вынесено решение.
func (r *Repo) UpsertVulnIndexVersion(ctx context.Context, v domain.VulnIndexVersion) (*domain.VulnIndexVersion, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO vuln_index_version
			(version, source, checksum, remote_path, local_path, published_at,
			 downloaded_at, record_count, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
		ON CONFLICT (version) DO UPDATE SET
			downloaded_at = EXCLUDED.downloaded_at, is_active = TRUE
		RETURNING id, version, source, checksum, remote_path, local_path,
		          published_at, downloaded_at, record_count, is_active
	`, v.Version, v.Source, v.Checksum, v.RemotePath, v.LocalPath,
		v.PublishedAt, time.Now().UTC(), v.RecordCount)

	var out domain.VulnIndexVersion
	if err := row.Scan(&out.ID, &out.Version, &out.Source, &out.Checksum, &out.RemotePath,
		&out.LocalPath, &out.PublishedAt, &out.DownloadedAt, &out.RecordCount, &out.IsActive); err != nil {
		return nil, fmt.Errorf("сохранение версии снапшота OSV: %w", err)
	}
	return &out, nil
}

// SetVersionVulnSummary — итог шага проверки уязвимостей на версии пакета.
func (r *Repo) SetVersionVulnSummary(ctx context.Context, packageVersionID int64, maxScore float64, indexVersionID *int64) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version
		SET max_vuln_score = $2, vuln_index_version_id = $3, updated_at = now()
		WHERE id = $1
	`, packageVersionID, maxScore, indexVersionID)
	if err != nil {
		return fmt.Errorf("сохранение итога проверки уязвимостей: %w", err)
	}
	return nil
}

// SetSecurityOverride — DevSecOps разрешил публикацию этой версии.
//
// Решение фиксируется на package_version, а не на request_item: оно вынесено
// по содержимому пакета и относится ко всем, кто заказал эту версию. Без этого
// возобновлённый конвейер снова упёрся бы в тот же вердикт сканера.
func (r *Repo) SetSecurityOverride(ctx context.Context, packageVersionID, actorID int64, comment string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET
			security_override_at = now(), security_override_by_id = $2,
			security_override_comment = $3, updated_at = now()
		WHERE id = $1
	`, packageVersionID, actorID, nullIfEmpty(comment))
	if err != nil {
		return fmt.Errorf("сохранение разрешения DevSecOps: %w", err)
	}
	return nil
}

// ClearSecurityOverride — снятие разрешения (отзыв версии, повторная проверка).
func (r *Repo) ClearSecurityOverride(ctx context.Context, packageVersionID int64) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET
			security_override_at = NULL, security_override_by_id = NULL,
			security_override_comment = NULL, updated_at = now()
		WHERE id = $1
	`, packageVersionID)
	if err != nil {
		return fmt.Errorf("снятие разрешения DevSecOps: %w", err)
	}
	return nil
}

// SetVersionLicense — подтверждённая лицензия версии и её источник.
func (r *Repo) SetVersionLicense(ctx context.Context, packageVersionID int64, spdx, source string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET license_spdx = $2, license_source = $3, updated_at = now()
		WHERE id = $1
	`, packageVersionID, nullIfEmpty(spdx), nullIfEmpty(source))
	if err != nil {
		return fmt.Errorf("сохранение лицензии версии: %w", err)
	}
	return nil
}

// SetPackageConfirmedLicense — подтверждённая лицензия предлагается для других
// версий этого пакета.
func (r *Repo) SetPackageConfirmedLicense(ctx context.Context, packageID int64, spdx, version string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package SET confirmed_license_spdx = $2, confirmed_license_version = $3, updated_at = now()
		WHERE id = $1
	`, packageID, nullIfEmpty(spdx), nullIfEmpty(version))
	if err != nil {
		return fmt.Errorf("сохранение подтверждённой лицензии пакета: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// FinishRequestItem — пакет заявки завершён решением роли (обычно отклонением).
func (r *Repo) FinishRequestItem(ctx context.Context, id int64, status, blockedReason, nextAction string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE request_item SET
			status = $2, blocked_reason = $3, next_action = $4,
			finished_at = $5, waiting_since = NULL, updated_at = now()
		WHERE id = $1
	`, id, status, nullIfEmpty(blockedReason), nullIfEmpty(nextAction), at)
	if err != nil {
		return fmt.Errorf("завершение пакета заявки: %w", err)
	}
	return nil
}

// MarkStepPassed — шаг отмечен пройденным после решения роли. Это и есть
// «снятие блокировки»: отдельной сущности нет, шаг считается непогашенным,
// пока его результат остаётся открытым.
func (r *Repo) MarkStepPassed(ctx context.Context, requestItemID int64, stepCode, message string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE pipeline_step SET result = 'pass', message = $3, finished_at = $4
		WHERE request_item_id = $1 AND step_code = $2
	`, requestItemID, stepCode, nullIfEmpty(message), at)
	if err != nil {
		return fmt.Errorf("снятие блокировки по шагу %s: %w", stepCode, err)
	}
	return nil
}

// ClearQuarantineUntil — срок карантина снят.
func (r *Repo) ClearQuarantineUntil(ctx context.Context, packageVersionID int64) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET quarantine_until = NULL, updated_at = now() WHERE id = $1
	`, packageVersionID)
	if err != nil {
		return fmt.Errorf("снятие срока карантина: %w", err)
	}
	return nil
}
