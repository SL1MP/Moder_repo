package pipeline

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"moderation/internal/dragon"
)

// DragonScanStep sends the downloaded Go module archive to Dragon. The step
// is informational by policy: submission errors, scanner failures and
// findings are recorded, but none of them may stop publication.
type DragonScanStep struct{}

func (DragonScanStep) Code() string { return "dragon_scan" }

func (DragonScanStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !pc.Config.DragonEnabled {
		return StepOutcome{
			Result:  "skipped",
			Message: "Информационное сканирование Dragon выключено настройкой DRAGON_ENABLED.",
			Details: map[string]any{"applicable": false},
		}, nil
	}
	if !dragonManagerSupported(pc.Package.Manager) {
		return StepOutcome{
			Result:  "skipped",
			Message: "Dragon применяется только к Go-модулям — шаг пропущен.",
			Details: map[string]any{"applicable": false, "manager": pc.Package.Manager},
		}, nil
	}
	if pc.Deps.Dragon == nil {
		return dragonInformation("Go-пакет не отправлен в Dragon: клиент не настроен.", nil, dragon.Result{}), nil
	}

	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil || artifact.StagingPath == nil || artifact.SHA256 == nil ||
		strings.TrimSpace(*artifact.StagingPath) == "" || strings.TrimSpace(*artifact.SHA256) == "" {
		return dragonInformation(
			"Go-пакет не отправлен в Dragon: архив или его SHA-256 отсутствует во временном хранилище.",
			nil, dragon.Result{}), nil
	}
	payload, err := pc.Payload(ctx, artifact)
	if err != nil {
		return dragonInformation("Go-пакет не отправлен в Dragon: архив не прочитан.", err, dragon.Result{}), nil
	}

	// Go-модули чувствительны к регистру: DisplayName хранит исходный путь,
	// тогда как Name нормализован для поиска в базе.
	name := strings.TrimSpace(pc.Package.DisplayName)
	if name == "" {
		name = strings.TrimSpace(pc.Package.Name)
	}
	size := int64(0)
	if artifact.SizeBytes != nil {
		size = *artifact.SizeBytes
	}
	result, scanErr := pc.Deps.Dragon.Scan(ctx, dragon.Request{
		PipelineID:   pc.Config.DragonPipelineID,
		RepositoryID: pc.Config.DragonRepositoryID,
		ExternalID:   "moderation:item:" + strconv.FormatInt(pc.Item.ID, 10) + ":sha256:" + *artifact.SHA256,
		Publish:      pc.Config.DragonPublish,
		Priority:     pc.Config.DragonPriority,
		Artifact: dragon.Artifact{
			Manager: pc.Package.Manager, Name: name,
			Version: pc.Version.RawVersion, Filename: artifact.Filename,
			SHA256: *artifact.SHA256, SizeBytes: size, Payload: payload,
		},
	})
	if scanErr != nil {
		message := "Go-пакет не удалось отправить в Dragon. Публикация продолжается, потому что Dragon — информационная проверка."
		if result.RunID != "" {
			message = "Dragon принял Go-пакет, но итог сканирования получить не удалось. Публикация продолжается."
		}
		return dragonInformation(message, scanErr, result), nil
	}

	message := fmt.Sprintf("Dragon завершил информационное сканирование Go-пакета со статусом %s.", result.Status)
	if strings.TrimSpace(result.Error) != "" {
		message += " Ошибка Dragon: " + result.Error + "."
	}
	if result.Findings.Total > 0 {
		message += fmt.Sprintf(
			" Найдено: уязвимостей — %d, секретов — %d, находок анализа кода — %d.",
			result.Findings.Vulnerabilities, result.Findings.Secrets, result.Findings.CodeFindings)
	} else {
		message += " По доступным логам счётчики находок равны нулю."
	}
	message += " Результат Dragon не блокирует публикацию пакета."
	return dragonInformation(message, nil, result), nil
}

func dragonInformation(message string, err error, result dragon.Result) StepOutcome {
	details := map[string]any{
		"applicable":        true,
		"blocking":          false,
		"run_id":            result.RunID,
		"run_url":           result.RunURL,
		"status_url":        result.StatusURL,
		"status":            result.Status,
		"done":              result.Done,
		"success":           result.Success,
		"dragon_error":      result.Error,
		"artifact_verified": result.ArtifactVerified,
		"findings":          result.Findings,
		"jobs":              dragonJobDetails(result.Jobs),
		"pipeline":          result.Pipeline,
		"repository":        result.Repo,
		"repository_id":     result.RepositoryID,
		"archive_sha256":    result.ArchiveSHA256,
		"archive_format":    result.ArchiveFormat,
		"archive_files":     result.ArchiveFiles,
		"archive_bytes":     result.ArchiveBytes,
		"archive_skipped":   result.ArchiveSkipped,
		"oakshield_url":     result.OakshieldURL,
	}
	if err != nil {
		details["error"] = err.Error()
		message += " Причина: " + err.Error()
	}
	return Info(message).WithDetails(details)
}

func dragonJobDetails(jobs []dragon.Job) []map[string]any {
	out := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, map[string]any{
			"id": job.ID, "name": job.Name, "stage": job.Stage,
			"scanner": job.Scanner, "status": job.Status, "duration": job.Duration,
			"allow_failure": job.AllowFailure, "test_id": job.TestID,
			"report_size": job.ReportSize, "report_deleted": job.ReportDeleted,
		})
	}
	return out
}

func dragonManagerSupported(manager string) bool {
	return strings.EqualFold(strings.TrimSpace(manager), "go")
}
