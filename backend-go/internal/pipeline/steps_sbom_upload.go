package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"moderation/internal/domain"
	"moderation/internal/sbom"
)

// SBOMUploadStep is a barrier after the parallel scanners. SBOM generation,
// OSV, sandbox, Dragon and license evaluation do not wait for each other;
// here their completed results are combined and the final CycloneDX document
// is sent to VuMana. VuMana remains informational, matching the supplied
// GitLab job where upload_sbom.py is invoked with `|| true`.
type SBOMUploadStep struct{}

func (SBOMUploadStep) Code() string { return "sbom_upload" }

func (SBOMUploadStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !sbom.Supports(pc.Package.Manager) || !pc.Config.SBOMEnabled {
		return StepOutcome{Result: "skipped", Message: "Выгружать SBOM нечего: формирование неприменимо или выключено.",
			Details: map[string]any{"applicable": sbom.Supports(pc.Package.Manager), "sbom_enabled": pc.Config.SBOMEnabled}}, nil
	}
	docs, err := pc.Deps.Repo.ListSBOMDocuments(ctx, pc.Item.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if len(docs) == 0 {
		return Fail("SBOM не выгружен: шаг формирования не создал документов.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку с шага «Формирование SBOM»."), nil
	}
	freshVersion, err := pc.Deps.Repo.GetPackageVersion(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if freshVersion == nil {
		return StepOutcome{}, fmt.Errorf("версия пакета #%d исчезла перед выгрузкой SBOM", pc.Version.ID)
	}
	findings, err := pc.Deps.Repo.ListVulnerabilities(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	vulnerabilities := sbomFindings(findings)

	type prepared struct {
		doc  domain.SBOMDocument
		body []byte
	}
	preparedDocs := make([]prepared, 0, len(docs))
	for _, doc := range docs {
		body, err := pc.Deps.Reports.Get(ctx, doc.StorageKey)
		if err != nil {
			return StepOutcome{}, fmt.Errorf("чтение SBOM %s: %w", doc.Filename, err)
		}
		enriched, err := sbom.Enrich(body, deref(freshVersion.LicenseSPDX),
			deref(freshVersion.LicenseRaw), vulnerabilities)
		if err != nil {
			return StepOutcome{}, fmt.Errorf("обогащение SBOM %s: %w", doc.Filename, err)
		}
		if _, err := pc.Deps.Reports.Put(ctx, doc.StorageKey, enriched,
			"application/json; charset=utf-8"); err != nil {
			return StepOutcome{}, fmt.Errorf("сохранение обогащённого SBOM %s: %w", doc.Filename, err)
		}
		digest := sha256.Sum256(enriched)
		doc.SizeBytes = int64(len(enriched))
		doc.SHA256 = hex.EncodeToString(digest[:])
		preparedDocs = append(preparedDocs, prepared{doc: doc, body: enriched})
	}
	updatedDocs := make([]domain.SBOMDocument, 0, len(preparedDocs))
	for _, prepared := range preparedDocs {
		updatedDocs = append(updatedDocs, prepared.doc)
	}
	if err := pc.Deps.Repo.ReplaceSBOMDocuments(ctx, pc.Item.ID, updatedDocs); err != nil {
		return StepOutcome{}, err
	}

	details := map[string]any{
		"documents": len(preparedDocs), "vulnerabilities": len(vulnerabilities),
		"enriched": true, "blocks_publication": false,
	}
	if !pc.Config.VumanaEnabled {
		details["enabled"] = false
		return StepOutcome{Result: "skipped",
			Message: fmt.Sprintf("SBOM обогащён результатами проверок (%d уязвимостей); выгрузка в VuMana выключена.", len(vulnerabilities)),
			Details: details}, nil
	}
	if pc.Deps.Vumana == nil || !pc.Deps.Vumana.Available() {
		details["error"] = "VUMANA_API_URL не задан"
		return Info("SBOM сформирован, но не отправлен в VuMana: интеграция не настроена. Публикация пакета продолжается.").
			WithDetails(details), nil
	}

	uploaded := make([]map[string]any, 0, len(preparedDocs))
	errors := make([]string, 0)
	for _, prepared := range preparedDocs {
		result, err := pc.Deps.Vumana.Upload(ctx, prepared.doc.Filename, prepared.body)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", prepared.doc.Filename, err))
			continue
		}
		uploaded = append(uploaded, map[string]any{
			"filename": prepared.doc.Filename, "id": result.ID,
			"url": result.URL, "browser_url": result.BrowserURL,
		})
	}
	details["uploaded"] = uploaded
	if len(errors) > 0 {
		details["errors"] = errors
		return Info(fmt.Sprintf(
			"VuMana приняла %d из %d SBOM; ошибки не блокируют публикацию пакета.",
			len(uploaded), len(preparedDocs))).WithDetails(details), nil
	}
	return Pass(fmt.Sprintf("В VuMana загружено SBOM: %d документ(а).", len(uploaded))).
		WithDetails(details), nil
}

func sbomFindings(findings []domain.Vulnerability) []sbom.Vulnerability {
	out := make([]sbom.Vulnerability, 0, len(findings))
	for _, finding := range findings {
		score := finding.Score / 10
		if finding.CVSSScore != nil {
			score = *finding.CVSSScore
		}
		out = append(out, sbom.Vulnerability{
			ID: finding.ExternalID, Aliases: finding.Aliases,
			Summary: deref(finding.Summary), URL: deref(finding.URL),
			Severity: deref(finding.Severity), CVSSVector: deref(finding.CVSSVector),
			CVSSScore: score, FixedVersions: finding.FixedVersions,
		})
	}
	return out
}
