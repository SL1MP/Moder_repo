package pipeline

import (
	"context"
	"fmt"

	"moderation/internal/domain"
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

	if pc.Deps.Artifacts.DryRun() {
		// Весь конвейер выполняется по-настоящему (реальное скачивание,
		// реальные сканеры) — не публикуем реальными байтами. Проверяем только
		// достижимость и авторизацию, чтобы креды боевого Artifactory были
		// проверены без риска записи.
		wouldBeURL := pc.Deps.Artifacts.ArtifactURL(repoName, path)
		authNote := "артефактори отвечает, доступ подтверждён"
		var reachable any
		if exists, err := pc.Deps.Artifacts.Exists(ctx, repoName, path); err != nil {
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
			},
			Terminal:   true,
			ItemStatus: "dry_run",
		}, nil
	}

	payload, err := pc.Payload(ctx, artifact)
	if err != nil {
		return StepOutcome{}, err
	}
	url, err := pc.Deps.Artifacts.Publish(ctx, repoName, path, payload)
	if err != nil {
		return Fail(fmt.Sprintf("Публикация в артефактори не удалась: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Сообщите администратору сервиса: артефактори отклонил выгрузку."), nil
	}

	if err := pc.Deps.Repo.MarkArtifactPublished(ctx, artifact.ID, url, pc.now()); err != nil {
		return StepOutcome{}, err
	}
	// Карантинная зона — временная: объект удаляется сразу после успешной
	// выгрузки. keepStatus=true, потому что статус уже published.
	if err := purgeArtifact(ctx, pc, artifact, true); err != nil {
		return StepOutcome{}, err
	}

	return StepOutcome{
		Result:  "pass",
		Message: fmt.Sprintf("Пакет опубликован во внутреннем репозитории %s: %s", repoName, url),
		Details: map[string]any{
			"nexus_url": url, "install_command": command, "repo": repoName,
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
