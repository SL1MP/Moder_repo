package pipeline

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"moderation/internal/dragon"
)

// DragonScanStep delegates execution to Dragon and applies the result locally.
// Dragon cannot publish a package and does not make the moderation decision.
type DragonScanStep struct{}

func (DragonScanStep) Code() string { return "dragon_scan" }

func (DragonScanStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !pc.Config.DragonEnabled {
		return StepOutcome{
			Result:  "skipped",
			Message: "Сканирование Dragon выключено настройкой DRAGON_ENABLED.",
			Details: map[string]any{"applicable": false},
		}, nil
	}
	if !dragonManagerSupported(pc.Package.Manager) {
		return StepOutcome{
			Result: "skipped",
			Message: fmt.Sprintf("Dragon не применяется к менеджеру %s.", pc.Package.Manager),
			Details: map[string]any{
				"applicable": false, "manager": pc.Package.Manager,
			},
		}, nil
	}
	if pc.Deps.Dragon == nil {
		return dragonUnavailable("Клиент Dragon не настроен.", nil), nil
	}

	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil || artifact.StagingPath == nil || artifact.SHA256 == nil ||
		strings.TrimSpace(*artifact.StagingPath) == "" || strings.TrimSpace(*artifact.SHA256) == "" {
		return dragonUnavailable(
			"Артефакт или его SHA-256 отсутствует в staging — Dragon нечего проверять.", nil), nil
	}

	size := int64(0)
	if artifact.SizeBytes != nil {
		size = *artifact.SizeBytes
	}
	result, scanErr := pc.Deps.Dragon.Scan(ctx, dragon.Request{
		PipelineID: pc.Config.DragonPipelineID,
		// The digest is part of the idempotency key: retrying the same bytes
		// reuses a run, while a registry republish cannot reuse evidence for an
		// older artifact that happened to belong to the same request item.
		ExternalID: "moderation:item:" + strconv.FormatInt(pc.Item.ID, 10) + ":sha256:" + *artifact.SHA256,
		Publish:    false,
		Artifact: dragon.Artifact{
			Manager: pc.Package.Manager, Name: pc.Package.DisplayName,
			Version: pc.Version.RawVersion, Filename: artifact.Filename,
			URL: stagingArtifactURL(pc.Config.DragonStagingURL, *artifact.StagingPath),
			SHA256: *artifact.SHA256, SizeBytes: size,
		},
	})
	if scanErr != nil {
		return dragonUnavailable("Dragon не завершил обязательное сканирование.", scanErr), nil
	}

	details := map[string]any{
		"run_id": result.RunID, "run_url": result.RunURL,
		"status": result.Status, "artifact_verified": result.ArtifactVerified,
		"evidence_complete": result.EvidenceComplete,
		"summary": result.Summary, "report_urls": result.ReportURLs,
		"threshold": normalizedDragonSeverity(pc.Config.DragonMinSeverity),
	}
	if !result.ArtifactVerified {
		details["reason"] = "dragon_unavailable"
		return dragonUnavailable(
			"Dragon не подтвердил SHA-256 скачанного артефакта — результат нельзя связать с проверяемыми байтами.",
			nil).WithDetails(details), nil
	}
	if !result.Success {
		details["reason"] = "dragon_unavailable"
		return dragonUnavailable(
			fmt.Sprintf("Dragon завершил сканирование со статусом %s.", result.Status), nil).
			WithDetails(details), nil
	}
	if !result.EvidenceComplete {
		details["reason"] = "dragon_unavailable"
		return dragonUnavailable(
			"Dragon выполнил сканеры, но не вернул полный нормализованный итог; автоматически считать пакет чистым нельзя.",
			nil).WithDetails(details), nil
	}

	blocking := dragonBlockingFindings(result.Summary, pc.Config.DragonMinSeverity)
	if blocking > 0 {
		message := fmt.Sprintf(
			"Dragon завершил сканирование и подтвердил SHA-256; найдено %d срабатываний, достигших порога %s.",
			blocking, normalizedDragonSeverity(pc.Config.DragonMinSeverity))
		if pc.SecurityOverride != nil {
			return Info(message + " Публикация разрешена DevSecOps вручную.").WithDetails(details), nil
		}
		return Pending(message).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Дождитесь решения DevSecOps по отчётам Dragon.").
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}

	return Pass(fmt.Sprintf(
		"Dragon завершил сканирование, подтвердил SHA-256 и не нашёл срабатываний уровня %s и выше.",
		normalizedDragonSeverity(pc.Config.DragonMinSeverity))).WithDetails(details), nil
}

func dragonUnavailable(message string, err error) StepOutcome {
	if err != nil {
		message += " Причина: " + err.Error()
	}
	return Pending(message).
		WithDetails(map[string]any{"reason": "dragon_unavailable"}).
		WithStatus("awaiting_security", "awaiting_security").
		WithNextAction("DevSecOps: восстановите Dragon и перезапустите этот шаг; без фактического сканирования публикация запрещена.").
		WithNotify(EventAwaitsSecurity, "devsecops")
}

func dragonManagerSupported(manager string) bool {
	switch manager {
	case "npm", "nuget", "pypi", "maven", "go", "conan", "docker":
		return true
	default:
		return false
	}
}

func stagingArtifactURL(base, key string) string {
	parts := strings.Split(strings.TrimLeft(key, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.TrimRight(base, "/") + "/" + strings.Join(parts, "/")
}

func normalizedDragonSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "high"
	}
}

func dragonBlockingFindings(summary dragon.Summary, threshold string) int {
	// Неизвестная серьёзность не означает низкую: пока классификация не
	// получена, находка требует решения DevSecOps при любом пороге.
	count := summary.Critical + summary.Unknown
	switch normalizedDragonSeverity(threshold) {
	case "critical":
		return count
	case "high":
		return count + summary.High
	case "medium":
		return count + summary.High + summary.Medium
	default:
		return count + summary.High + summary.Medium + summary.Low
	}
}

