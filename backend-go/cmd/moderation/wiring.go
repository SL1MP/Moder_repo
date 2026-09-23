package main

import (
	"fmt"
	"net/http"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/config"
	"moderation/internal/pipeline"
	"moderation/internal/sandbox"
	"moderation/internal/storage"
)

// Сборка внешних зависимостей в одном месте.
//
// Раньше клиент артефактори и хранилище собирались в четырёх командах по
// отдельности (api, worker, scan, maintenance), и каждая новая настройка
// требовала четырёх одинаковых правок. Так уже разъехались параметры:
// ARTIFACT_DRY_RUN учитывался не везде. Здесь они собираются один раз.

// newArtifactStore — клиент артефактори. Один на процесс: и публикация
// пакетов, и промежуточная зона, и отчёты ходят в одну систему по одним
// учётным данным.
func newArtifactStore(cfg *config.Config, httpClient *http.Client) (artifactstore.Store, error) {
	return artifactstore.New(artifactstore.Config{
		Kind:    cfg.ArtifactStore,
		BaseURL: cfg.ArtifactBaseURL,
		// Password: тот же токен — так же, как это делалось во всех четырёх
		// прежних копиях. Artifactory принимает токен и как пароль basic-auth.
		AuthType: artifactstore.AuthType(cfg.ArtifactAuthType),
		Token:    cfg.ArtifactToken, Username: cfg.ArtifactUser, Password: cfg.ArtifactToken,
		DryRun: cfg.ArtifactDryRun, HTTPClient: httpClient,
	})
}

// stores — хранилища сервиса, оба поверх артефактори.
type stores struct {
	// Artifacts — клиент артефактори: публикация пакетов и снапшот OSV.
	Artifacts artifactstore.Store
	// Staging — промежуточная зона: скачанный пакет лежит в ней, пока идут
	// проверки.
	Staging storage.Staging
	// Reports — отчёты сканирования, живущие дольше артефакта.
	Reports storage.Store
}

// newStores собирает оба хранилища.
//
// DryRun сознательно НЕ влияет на промежуточную зону и отчёты: «проверить
// доступ, но не публиковать» относится к целевому репозиторию, из которого
// разработчики ставят пакеты. Прогон, который не скачал артефакт и не написал
// отчёт, проверяет не конвейер, а самого себя.
func newStores(cfg *config.Config, httpClient *http.Client) (*stores, error) {
	artifacts, err := newArtifactStore(cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("артефактори: %w", err)
	}
	// Отдельный клиент без dry-run: запись в промежуточную зону и в отчёты
	// обязана происходить по-настоящему даже тогда, когда публикация
	// пропускается.
	rawCfg := *cfg
	rawCfg.ArtifactDryRun = false
	raw, err := newArtifactStore(&rawCfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("артефактори (служебные репозитории): %w", err)
	}

	staging, err := storage.NewArtifactory(storage.ArtifactoryConfig{
		Store: raw, Repo: cfg.ArtifactRepoStaging,
	})
	if err != nil {
		return nil, fmt.Errorf("промежуточная зона: %w", err)
	}
	reports, err := storage.NewArtifactory(storage.ArtifactoryConfig{
		Store: raw, Repo: cfg.ArtifactRepoReports,
	})
	if err != nil {
		return nil, fmt.Errorf("хранилище отчётов: %w", err)
	}
	return &stores{Artifacts: artifacts, Staging: staging, Reports: reports}, nil
}

// newSandbox — клиент песочницы шага sandbox_scan. Ошибки нет намеренно:
// ненастроенная песочница не повод не стартовать, это повод шагу сказать
// «проверить нечем» и позвать DevSecOps.
func newSandbox(cfg *config.Config) sandbox.Client {
	return sandbox.New(sandbox.Config{
		BaseURL: cfg.SandboxURL, Token: cfg.SandboxToken,
		Priority: cfg.SandboxPriority, ShortResult: cfg.SandboxShortResult,
		Timeout: cfg.SandboxTimeout, InsecureTLS: cfg.SandboxInsecureTLS,
	})
}

// pipelineConfig — пороги и переключатели конвейера из конфигурации сервиса.
// Одна функция на все команды: разные значения в api и worker означали бы
// разный вердикт по одному пакету в зависимости от того, кто его проверил.
func pipelineConfig(cfg *config.Config) pipeline.Config {
	return pipeline.Config{
		ArtifactBaseURL: cfg.ArtifactBaseURL,
		ArtifactRepos:   cfg.ArtifactRepos,

		QuarantineDays:       cfg.QuarantineDays,
		VulnMaxScore:         cfg.VulnMaxScore,
		OSVMaxStalenessDays:  cfg.OSVMaxStalenessDays,
		MaxArtifactSizeBytes: cfg.MaxArtifactSizeBytes,

		SandboxEnabled: cfg.SandboxEnabled,

		// Снятые шаги: конвейер их не запускает, значения переносятся, чтобы
		// возврат шага в строй не требовал ещё и правки сборки.
		BannerScanEnabled: cfg.BannerScanEnabled,
		SASTEnabled:       cfg.SASTEnabled,
		SASTMinSeverity:   cfg.SASTMinSeverity,

		ScanMaxUnpackedBytes: cfg.ScanMaxUnpackedBytes,
		ScanMaxFiles:         cfg.ScanMaxFiles,
	}
}

// storeProbeTimeout — сколько ждать ответа артефактори при проверке
// доступности хранилища на старте. Коротко намеренно: это проверка, а не
// работа, и висеть на ней запуск сервиса не должен.
const storeProbeTimeout = 10 * time.Second

// newHTTPClient — клиент для походов наружу. Таймаут общий: реестры,
// артефактори и песочница ходят через один корпоративный прокси, и разные
// таймауты у них означали бы разное поведение при одной и той же недоступности
// сети. Песочница собирает себе свой — её запрос длится минутами.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}
