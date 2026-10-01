package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"moderation/internal/domain"
	"moderation/internal/sbom"
	"moderation/internal/storage"
)

// SBOMStep builds CycloneDX from the exact bytes produced by DownloadStep.
// It deliberately runs before PublishStep: publication must never silently
// succeed without the SBOM requested for this manager.
type SBOMStep struct{}

func (SBOMStep) Code() string { return "sbom" }

func (SBOMStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !sbom.Supports(pc.Package.Manager) {
		return StepOutcome{
			Result: "skipped",
			Message: fmt.Sprintf("Формирование SBOM не применяется к менеджеру %s.", pc.Package.Manager),
			Details: map[string]any{"applicable": false, "manager": pc.Package.Manager},
		}, nil
	}
	if !pc.Config.SBOMEnabled {
		return StepOutcome{
			Result: "skipped", Message: "Формирование SBOM выключено настройкой (SBOM_ENABLED=false).",
			Details: map[string]any{"applicable": true, "enabled": false},
		}, nil
	}
	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil { return StepOutcome{}, err }
	if artifact == nil {
		return Fail("Артефакт для формирования SBOM не найден — шаг скачивания не выполнен.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку с шага скачивания."), nil
	}
	payload, err := pc.Payload(ctx, artifact)
	if err != nil { return StepOutcome{}, err }
	// A restarted check must not expose documents from the previous run while
	// the new generator is working or after it fails.
	oldDocs, err := pc.Deps.Repo.ListSBOMDocuments(ctx, pc.Item.ID)
	if err != nil { return StepOutcome{}, err }
	if err := pc.Deps.Repo.DeleteSBOMDocuments(ctx, pc.Item.ID); err != nil {
		return StepOutcome{}, err
	}
	for _, old := range oldDocs { _ = pc.Deps.Reports.Delete(ctx, old.StorageKey) }

	docs, err := pc.Deps.SBOM.Generate(ctx, sbom.Input{
		Manager: pc.Package.Manager, Name: pc.Package.Name, DisplayName: pc.Package.DisplayName,
		Version: pc.Version.Version, RawVersion: pc.Version.RawVersion,
		LicenseSPDX: deref(pc.Version.LicenseSPDX), LicenseRaw: deref(pc.Version.LicenseRaw),
		ArtifactSHA256: deref(artifact.SHA256), Payload: payload,
	})
	if err != nil { return StepOutcome{}, fmt.Errorf("формирование SBOM: %w", err) }
	if len(docs) == 0 { return StepOutcome{}, fmt.Errorf("генератор SBOM не вернул ни одного документа") }

	written := make([]domain.SBOMDocument, 0, len(docs))
	storedKeys := make([]string, 0, len(docs))
	cleanupStored := func() {
		for _, key := range storedKeys { _ = pc.Deps.Reports.Delete(ctx, key) }
	}
	for _, doc := range docs {
		if doc.Filename == "" || len(doc.Body) == 0 {
			cleanupStored()
			return StepOutcome{}, fmt.Errorf("генератор SBOM вернул пустой документ")
		}
		key := storage.SBOMKey(pc.Item.ID, doc.Filename)
		if _, err := pc.Deps.Reports.Put(ctx, key, doc.Body, "application/json; charset=utf-8"); err != nil {
			cleanupStored()
			return StepOutcome{}, fmt.Errorf("запись SBOM %s: %w", doc.Filename, err)
		}
		storedKeys = append(storedKeys, key)
		digest := sha256.Sum256(doc.Body)
		written = append(written, domain.SBOMDocument{
			RequestItemID: pc.Item.ID, PackageVersionID: pc.Version.ID,
			Manager: pc.Package.Manager, Platform: doc.Platform, Filename: doc.Filename,
			Format: "cyclonedx-json", SpecVersion: doc.SpecVersion, StorageKey: key,
			SizeBytes: int64(len(doc.Body)), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if err := pc.Deps.Repo.ReplaceSBOMDocuments(ctx, pc.Item.ID, written); err != nil {
		cleanupStored()
		return StepOutcome{}, err
	}
	views := make([]map[string]any, 0, len(written))
	for _, doc := range written {
		views = append(views, map[string]any{
			"filename": doc.Filename, "platform": doc.Platform,
			"sha256": doc.SHA256, "size_bytes": doc.SizeBytes,
		})
	}
	message := fmt.Sprintf("Сформирован CycloneDX SBOM: %d документ(а).", len(written))
	if pc.Package.Manager == "docker" {
		message = fmt.Sprintf("Сформирован CycloneDX SBOM для %d платформ Docker-образа.", len(written))
	}
	return Pass(message).WithDetails(map[string]any{"documents": views, "format": "cyclonedx-json"}), nil
}
