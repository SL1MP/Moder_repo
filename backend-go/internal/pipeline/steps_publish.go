package pipeline

import (
	"context"
	"fmt"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
	"moderation/internal/storage"
)

// --------------------------------------------------------------------------- шаг 8
// PublishStep — выгрузка в артефактори.
type PublishStep struct{}

func (PublishStep) Code() string { return "publish" }

func (PublishStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	// Заявку могли закрыть, пока шёл прогон. Статус читаем из базы заново:
	// pc.Item — снимок на момент захвата, и отмена, пришедшая после него, в
	// нём не видна.
	//
	// Прогон и так прекращается, когда строку «отбирают» (Queue.Heartbeat
	// возвращает false), но отметка о жизни редкая — раз в 30 секунд, — и
	// публикация может успеть проскочить в этот зазор. Опубликовать пакет,
	// который автор только что отменил, нельзя: это запись во внешний
	// артефактори, её потом не отозвать одним UPDATE.
	fresh, err := pc.Deps.Repo.GetRequestItem(ctx, pc.Item.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if fresh != nil && fresh.Status == "cancelled" {
		return Warn("Публикация отменена: заявка закрыта автором.").
			WithStatus("cancelled", "").
			WithNextAction("Пакет больше не нужен автору заявки. " +
				"Чтобы получить его, создайте новую заявку."), nil
	}

	// Согласования идут параллельно, поэтому к публикации пакет может прийти с
	// непогашенной блокировкой — например, уязвимости проверены, а лицензия
	// ещё у юриста. Публиковать в этом случае нельзя.
	steps, err := pc.Deps.Repo.ListStepsByItem(ctx, pc.Item.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if blockers := PendingBlockers(steps); len(blockers) > 0 {
		return blockedOutcome(blockers), nil
	}

	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil {
		return Fail("Артефакт для публикации не найден.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку заявки."), nil
	}

	plugin, err := pc.Plugin()
	if err != nil {
		return StepOutcome{}, err
	}
	ref := pc.Ref()
	repoName := pc.Config.ArtifactRepo(pc.Package.Manager)
	path := plugin.ArtifactPath(ref, artifact.Filename)
	command := plugin.InstallCommand(ref, pc.Config.ArtifactBaseURL, repoName)
	// Цель публикации несёт и пакет, и путь: раскладка внутри репозитория
	// зависит от типа артефактори (Nexus строит её сам по формату), а путь от
	// плагина — это раскладка Artifactory.
	target := artifactstore.Target{
		Repo: repoName, Manager: ref.Manager, Name: ref.Name, DisplayName: ref.DisplayName,
		Version: ref.RawVersion, Filename: artifact.Filename, Path: path,
	}

	if pc.Deps.Artifacts.DryRun() {
		// Весь конвейер выполняется по-настоящему (реальное скачивание,
		// реальные сканеры) — не публикуем реальными байтами. Проверяем только
		// достижимость и авторизацию, чтобы креды боевого Artifactory были
		// проверены без риска записи.
		wouldBeURL := pc.Deps.Artifacts.ArtifactURL(target)
		authNote := "артефактори отвечает, доступ подтверждён"
		var reachable any
		if exists, err := pc.Deps.Artifacts.Exists(ctx, target); err != nil {
			authNote = fmt.Sprintf("проверка достижимости не удалась: %v", err)
		} else {
			reachable = exists
		}
		// Статус заявки сознательно НЕ переводим в approved: публикации не
		// было, реального артефакта по команде установки ещё нет.
		return StepOutcome{
			Result: "pass",
			Message: fmt.Sprintf(
				"[dry-run] Публикация пропущена (ARTIFACT_DRY_RUN=true). Был бы опубликован по %s. %s.",
				wouldBeURL, authNote),
			Details: map[string]any{
				"dry_run": true, "would_be_url": wouldBeURL, "already_exists": reachable,
				"install_command_if_published": command, "repo": repoName,
				"artifact_store": pc.Deps.Artifacts.Kind(),
			},
			Terminal:   true,
			ItemStatus: "dry_run",
		}, nil
	}

	url, how, err := publishArtifact(ctx, pc, artifact, target)
	if err != nil {
		return Fail(fmt.Sprintf("Публикация в артефактори не удалась: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Сообщите администратору сервиса: артефактори отклонил выгрузку."), nil
	}

	if err := pc.Deps.Repo.MarkArtifactPublished(ctx, artifact.ID, url, pc.now()); err != nil {
		return StepOutcome{}, err
	}
	// Промежуточная зона — временная: файл уходит из неё сразу после успешной
	// публикации. При переносе он оттуда уже исчез (артефактори переложил его
	// сам), при выгрузке копией — удаляем. purgeArtifact в обоих случаях
	// проставит отметку об очистке; keepStatus=true, потому что статус уже
	// published.
	if err := clearStaging(ctx, pc, artifact, how); err != nil {
		return StepOutcome{}, err
	}

	return StepOutcome{
		Result: "pass",
		Message: fmt.Sprintf("Пакет опубликован во внутреннем репозитории %s (%s): %s",
			repoName, how.title(), url),
		Details: map[string]any{
			"nexus_url": url, "install_command": command, "repo": repoName,
			"publish_mode": string(how),
		},
		Terminal:      true,
		ItemStatus:    "approved",
		VersionStatus: "approved",
		NextAction:    "Устанавливайте из внутреннего репозитория: " + command,
		NotifyEvent:   EventPackageApproved,
	}, nil
}

// blockedOutcome — публикация отложена: какое-то согласование ещё не получено.
//
// Роль и статус берутся из общих справочников в blockers.go. Держать здесь
// свою копию нельзя: при добавлении шага она разъезжается с основной, и
// конвейер падает на неизвестном коде (в Python-версии это уже случилось).
func blockedOutcome(blockers []string) StepOutcome {
	primary := blockers[0]
	status := BlockerStatus[primary]
	who := BlockerWaitingFor[primary]
	role := BlockerRole[primary]

	event := EventDecisionMade
	switch role {
	case "legal":
		event = EventAwaitsLegal
	case "devsecops":
		event = EventAwaitsSecurity
	}

	names := make([]string, 0, len(blockers))
	for _, code := range blockers {
		names = append(names, domain.StepTitles[code])
	}

	outcome := StepOutcome{
		Result: "warn",
		Message: fmt.Sprintf(
			"Публикация отложена: не получено согласование по шагам — %s. Ожидается решение: %s.",
			joinComma(names), who),
		Details:       map[string]any{"pending": blockers},
		Stop:          true,
		ItemStatus:    status,
		VersionStatus: status,
		NextAction: fmt.Sprintf(
			"Пакет проверен, но ждёт решения (%s). Как только согласование будет получено, "+
				"публикация пройдёт автоматически.", who),
		NotifyEvent: event,
	}
	if role != "" {
		outcome.NotifyRoles = []string{role}
	}
	return outcome
}

// --------------------------------------------------------------------------- как публикуем

// publishMode — каким способом пакет попал в целевой репозиторий.
//
// Различать обязательно, и не ради статистики: после переноса файла в
// промежуточной зоне его уже нет, а после выгрузки копией — есть, и удалять
// его надо. Перепутать значит либо оставить мусор в зоне навсегда, либо
// получать 404 на каждом удалении.
type publishMode string

const (
	// publishByMove — артефактори переложил файл у себя, байты через сервис не
	// проходили. Так работает CI-версия, и так дешевле всего: образ Docker или
	// jar с зависимостями незачем качать второй раз ради того, чтобы положить
	// рядом.
	publishByMove publishMode = "move"
	// publishByUpload — сервис прочитал файл из промежуточной зоны и выгрузил
	// его в целевой репозиторий. Запасной путь: так публикуется всё в Nexus
	// (переносить между репозиториями он не умеет) и всё, что артефактори
	// отказался переносить сам.
	publishByUpload publishMode = "upload"
)

func (m publishMode) title() string {
	if m == publishByMove {
		return "перенос внутри артефактори"
	}
	return "выгрузка из промежуточной зоны"
}

// publishArtifact кладёт пакет в целевой репозиторий, предпочитая перенос.
//
// Порядок именно такой: сначала пробуем перенос, и только если артефактори так
// не умеет — выгружаем копией. Обратный порядок («всегда выгружаем, перенос
// потом») означал бы, что дешёвый путь не используется никогда, а он и есть
// штатный для Artifactory.
func publishArtifact(
	ctx context.Context, pc *Context, artifact *domain.Artifact, target artifactstore.Target,
) (string, publishMode, error) {
	staging, ok := pc.Deps.Storage.(storage.Staging)
	canMove := ok && artifact.StagingPath != nil && *artifact.StagingPath != "" &&
		artifact.StagingClearedAt == nil
	if canMove {
		dstPath := targetPath(pc.Deps.Artifacts, target)
		err := staging.Move(ctx, *artifact.StagingPath, target.Repo, dstPath)
		switch {
		case err == nil:
			return pc.Deps.Artifacts.ArtifactURL(target), publishByMove, nil
		case storage.MoveUnsupported(err):
			// Штатный случай, не авария: Nexus так не умеет, и совместимые с
			// Artifactory только по PUT — тоже. Идём запасным путём молча:
			// сообщать об этом на каждом пакете нечего, способ публикации и так
			// попадает в details шага.
		default:
			return "", "", err
		}
	}

	payload, err := pc.Payload(ctx, artifact)
	if err != nil {
		return "", "", err
	}
	url, err := pc.Deps.Artifacts.Publish(ctx, target, payload)
	if err != nil {
		return "", "", err
	}
	return url, publishByUpload, nil
}

// targetPath — путь файла в целевом репозитории. У generic-артефактори это
// путь от плагина менеджера; Nexus раскладку строит сам, и перенос туда всё
// равно не поддержан — значение используется только в ветке переноса.
func targetPath(store artifactstore.Store, target artifactstore.Target) string {
	if target.Path != "" {
		return target.Path
	}
	// Пустой путь означал бы запись в корень репозитория. Плагин менеджера
	// обязан его дать; если не дал — кладём хотя бы по имени файла, а не в
	// корень с пустым именем.
	_ = store
	return target.Filename
}

// clearStaging убирает файл из промежуточной зоны после публикации.
//
// После переноса файла в зоне уже нет — удалять нечего, но отметку об очистке
// поставить надо, иначе уборка будет вечно находить «забытый» артефакт и
// пытаться удалить то, чего нет.
func clearStaging(ctx context.Context, pc *Context, artifact *domain.Artifact, how publishMode) error {
	if how == publishByMove {
		return markStagingCleared(ctx, pc, artifact)
	}
	return purgeArtifact(ctx, pc, artifact, true)
}
