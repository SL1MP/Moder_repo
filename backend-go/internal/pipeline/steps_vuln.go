package pipeline

import (
	"context"
	"fmt"

	"moderation/internal/domain"
	"moderation/internal/osv"
)

// --------------------------------------------------------------------------- шаг 5
// VulnScanStep — проверка на уязвимости по снапшоту OSV.
//
// Два исхода приводят к DevSecOps, а не к отказу: устаревшая (или
// отсутствующая) база — warn, и балл выше порога — fail. Оба считаются
// непогашенной блокировкой (см. OpenResults), потому что решение по ним
// принимает человек.
type VulnScanStep struct{}

func (VulnScanStep) Code() string { return "vuln_scan" }

func (VulnScanStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil {
		return Fail("Артефакт для проверки не найден — шаг скачивания не выполнен.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку заявки."), nil
	}

	info, err := pc.Deps.Index.CurrentVersion(ctx)
	if err != nil {
		return StepOutcome{}, fmt.Errorf("чтение версии снапшота OSV: %w", err)
	}

	var indexVersionID *int64
	if info != nil {
		row, err := pc.Deps.Repo.UpsertVulnIndexVersion(ctx, domain.VulnIndexVersion{
			Version: info.Version, Source: info.Source,
			Checksum: nilIfEmpty(info.Checksum), RemotePath: nilIfEmpty(info.RemotePath),
			LocalPath: nilIfEmpty(info.LocalPath), PublishedAt: info.PublishedAt,
			RecordCount: ptr(info.RecordCount),
		})
		if err != nil {
			return StepOutcome{}, err
		}
		indexVersionID = &row.ID
	}

	maxDays := pc.Config.OSVMaxStalenessDays
	if maxDays <= 0 {
		maxDays = 7
	}
	stale, err := osv.IsStale(ctx, pc.Deps.Index, maxDays, pc.now())
	if err != nil {
		return StepOutcome{}, err
	}

	// Сканировать есть смысл, только если данные вообще загружены: по
	// отсутствующему снапшоту запрос вернёт ошибку, а недоступная база — не
	// авария, а повод отдать решение DevSecOps.
	var findings []osv.Finding
	scanError := ""
	if info != nil {
		findings, err = pc.Deps.Index.Query(ctx, pc.Package.Manager, pc.Package.Name, pc.Version.Version)
		if err != nil {
			if !stale {
				// База свежая, а запрос не удался — это уже настоящая ошибка.
				return StepOutcome{}, fmt.Errorf("запрос к снапшоту OSV: %w", err)
			}
			scanError = err.Error()
		}
	} else {
		scanError = "снапшот базы OSV ни разу не загружался"
	}

	if err := storeVulnerabilities(ctx, pc, findings, indexVersionID); err != nil {
		return StepOutcome{}, err
	}
	if err := pc.Deps.Repo.SetArtifactStatus(ctx, artifact.ID, "scanned"); err != nil {
		return StepOutcome{}, err
	}

	worst := osv.MaxScore(findings)
	if err := pc.Deps.Repo.SetVersionVulnSummary(ctx, pc.Version.ID, worst, indexVersionID); err != nil {
		return StepOutcome{}, err
	}
	pc.Version.MaxVulnScore = &worst
	pc.Version.VulnIndexVersionID = indexVersionID

	summary := osv.Summary(findings)
	indexVersion := "н/д"
	if info != nil {
		indexVersion = info.Version
	}

	// Решение DevSecOps важнее вердикта шага: иначе возобновление конвейера
	// снова остановилось бы здесь по той же причине, и решение не сработало бы.
	// Проверка сделана один раз в runner (см. Run), сюда приходит готовый
	// Override.
	if pc.SecurityOverride != nil {
		return Pass(fmt.Sprintf("Публикация разрешена вручную (%s): %s.%s",
			pc.SecurityOverride.DecidedBy, commentOr(pc.SecurityOverride.Comment),
			suffixIf(summary, " Известные уязвимости: "+summary+"."))).
			WithDetails(map[string]any{
				"reason": "security_override", "decided_by": pc.SecurityOverride.DecidedBy,
				"max_score": worst, "findings": summary, "index_version": indexVersion,
			}), nil
	}

	threshold := pc.Config.VulnMaxScore
	if stale {
		// Молча одобрять на устаревших данных нельзя.
		ageText := "снапшот не загружен"
		if info != nil {
			if age := info.AgeDays(pc.now()); age != nil {
				ageText = fmt.Sprintf("%.1f дн.", *age)
			}
		}
		return Warn(fmt.Sprintf(
			"База уязвимостей устарела (%s, допустимо %d дн.) — автоматическое одобрение отключено.%s%s",
			ageText, maxDays,
			suffixIf(summary, " Найдено: "+summary+"."),
			suffixIf(scanError, " Проверка не выполнена: "+scanError+"."))).
			WithDetails(map[string]any{
				"reason": "stale_index", "index_version": indexVersion,
				"findings": summary, "scan_error": scanError,
			}).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Дождитесь решения DevSecOps: решение по устаревшей базе принимается вручную.").
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}

	if worst > threshold {
		// Отклонение на шаге 5: объект из карантинной зоны удаляется сразу.
		if err := purgeArtifact(ctx, pc, artifact, false); err != nil {
			return StepOutcome{}, err
		}
		fixed := collectFixed(findings)
		advice := "(исправленных версий нет)"
		if fixed != "" {
			advice = fixed
		}
		return Fail(fmt.Sprintf(
			"Найдены уязвимости с баллом выше порога %g: %s. Решение вынесено по снапшоту OSV %s.",
			threshold, summary, indexVersion)).
			WithDetails(map[string]any{
				"max_score": worst, "threshold": threshold,
				"index_version": indexVersion, "findings": summary,
			}).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Возьмите версию с исправлением "+advice+
				" либо дождитесь решения DevSecOps.").
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}

	return Pass(fmt.Sprintf("Уязвимостей выше порога %g не найдено%s. Снапшот OSV: %s.",
		threshold, suffixIf(summary, " (учтено: "+summary+")"), indexVersion)).
		WithDetails(map[string]any{
			"max_score": worst, "threshold": threshold,
			"index_version": indexVersion, "findings_count": len(findings),
		}), nil
}

func storeVulnerabilities(ctx context.Context, pc *Context, findings []osv.Finding, indexVersionID *int64) error {
	if len(findings) == 0 {
		return nil
	}
	rows := make([]domain.Vulnerability, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, domain.Vulnerability{
			PackageVersionID: pc.Version.ID,
			ExternalID:       f.ExternalID,
			Aliases:          f.Aliases,
			Summary:          nilIfEmpty(f.Summary),
			CVSSVector:       nilIfEmpty(f.CVSSVector),
			CVSSScore:        ptr(f.CVSSScore),
			Score:            f.Score(),
			Severity:         nilIfEmpty(f.Severity),
			URL:              nilIfEmpty(f.URL),
			FixedVersions:    f.FixedVersions,
		})
	}
	return pc.Deps.Repo.UpsertVulnerabilities(ctx, pc.Version.ID, rows, indexVersionID)
}

func collectFixed(findings []osv.Finding) string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range findings {
		for _, v := range f.FixedVersions {
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return joinComma(out)
}

func joinComma(values []string) string {
	result := ""
	for i, v := range values {
		if i > 0 {
			result += ", "
		}
		result += v
	}
	return result
}

func suffixIf(condition, text string) string {
	if condition == "" {
		return ""
	}
	return text
}

func commentOr(comment string) string {
	if comment == "" {
		return "без комментария"
	}
	return comment
}
