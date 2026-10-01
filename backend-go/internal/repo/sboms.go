package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

const sbomColumns = `id, request_item_id, package_version_id, manager, platform,
filename, format, spec_version, storage_key, size_bytes, sha256, created_at`

func (r *Repo) DeleteSBOMDocuments(ctx context.Context, itemID int64) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sbom_document WHERE request_item_id = $1`, itemID); err != nil {
		return fmt.Errorf("удаление индекса SBOM: %w", err)
	}
	return nil
}

// ReplaceSBOMDocuments атомарно заменяет индекс документов одного прогона.
// Файлы в хранилище записываются до вызова; старые ключи удаляет шаг SBOM.
func (r *Repo) ReplaceSBOMDocuments(ctx context.Context, itemID int64, docs []domain.SBOMDocument) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало замены SBOM: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM sbom_document WHERE request_item_id = $1`, itemID); err != nil {
		return fmt.Errorf("удаление прежнего индекса SBOM: %w", err)
	}
	for i := range docs {
		d := docs[i]
		if _, err := tx.Exec(ctx, `
			INSERT INTO sbom_document
				(request_item_id, package_version_id, manager, platform, filename,
				 format, spec_version, storage_key, size_bytes, sha256)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		`, d.RequestItemID, d.PackageVersionID, d.Manager, d.Platform, d.Filename,
			d.Format, d.SpecVersion, d.StorageKey, d.SizeBytes, d.SHA256); err != nil {
			return fmt.Errorf("сохранение индекса SBOM %s: %w", d.Filename, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация индекса SBOM: %w", err)
	}
	return nil
}

func (r *Repo) ListSBOMDocuments(ctx context.Context, itemID int64) ([]domain.SBOMDocument, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+sbomColumns+`
		FROM sbom_document WHERE request_item_id = $1 ORDER BY platform, id`, itemID)
	if err != nil {
		return nil, fmt.Errorf("чтение SBOM: %w", err)
	}
	defer rows.Close()
	var out []domain.SBOMDocument
	for rows.Next() {
		d, err := scanSBOM(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (r *Repo) GetSBOMDocument(ctx context.Context, itemID int64, filename string) (*domain.SBOMDocument, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+sbomColumns+`
		FROM sbom_document WHERE request_item_id = $1 AND filename = $2`, itemID, filename)
	d, err := scanSBOM(row)
	if err != nil {
		// API превращает отсутствие в 404; используем nil без протаскивания
		// pgx.ErrNoRows наружу, как CurrentArtifact и GetScanReport.
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

func scanSBOM(row scanner) (*domain.SBOMDocument, error) {
	var d domain.SBOMDocument
	if err := row.Scan(&d.ID, &d.RequestItemID, &d.PackageVersionID, &d.Manager,
		&d.Platform, &d.Filename, &d.Format, &d.SpecVersion, &d.StorageKey,
		&d.SizeBytes, &d.SHA256, &d.CreatedAt); err != nil {
		return nil, fmt.Errorf("чтение sbom_document: %w", err)
	}
	return &d, nil
}
