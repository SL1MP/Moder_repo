package pipeline

import (
	"context"
	"fmt"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/scanners"
	"moderation/internal/storage"
)

// Config — пороги и переключатели конвейера. Целевой источник — БД/admin API
// (docs/configuration-model.md), не .env: здесь просто структура значений,
// откуда они берутся, решает вызывающий код.
type Config struct {
	QuarantineDays int

	// MaxArtifactSizeBytes — предел размера скачиваемого артефакта.
	MaxArtifactSizeBytes int64

	// VulnMaxScore — порог балла уязвимости (шкала 0..100), выше которого
	// пакет отклоняется. OSVMaxStalenessDays — допустимый возраст снапшота.
	VulnMaxScore        float64
	OSVMaxStalenessDays int

	// BannerScanEnabled/SASTEnabled — выключатели шагов сканирования.
	// SAST временно выключен целиком решением пользователя; код поддерживает
	// чистое выключение — шаг отдаёт pass с явной пометкой, а не молча
	// пропускается.
	BannerScanEnabled bool
	SASTEnabled       bool
	// SASTMinSeverity — порог SAST. У баннеров порога нет: совпадение правила
	// само по себе находка.
	SASTMinSeverity string

	// Пределы распаковки для сканирования содержимого.
	ScanMaxUnpackedBytes int64
	ScanMaxFiles         int

	// ArtifactBaseURL и ArtifactRepos — адрес артефактори и репозиторий на
	// каждый менеджер (ключ — код менеджера).
	ArtifactBaseURL string
	ArtifactRepos   map[string]string
}

// ArtifactRepo — целевой репозиторий артефактори для менеджера.
func (c Config) ArtifactRepo(manager string) string {
	if repoName, ok := c.ArtifactRepos[manager]; ok && repoName != "" {
		return repoName
	}
	return manager + "-internal"
}

// Deps — внешние зависимости конвейера. Все интерфейсы: конвейер не знает, что
// под ними — реальное хранилище или память.
type Deps struct {
	Repo      *repo.Repo
	Storage   storage.Store
	Artifacts artifactstore.Store
	Index     osv.Index
	Registry  *registry.Registry
	Banner    scanners.Scanner
	SAST      scanners.Scanner
	// Fetch скачивает артефакт по адресу из реестра. Отдельно от Registry:
	// качаем напрямую из реестра пакетного менеджера через корпоративный
	// HTTP_PROXY, а не через proxy-репозиторий артефактори.
	Fetch Fetcher
	// Now подменяется в тестах.
	Now func() time.Time
}

// Fetcher — скачивание артефакта. limit — предел размера; превышение обязано
// быть ошибкой, а не обрезанным файлом.
type Fetcher interface {
	Fetch(ctx context.Context, url string, limit int64) ([]byte, error)
}

// Context — то, с чем работает шаг.
type Context struct {
	Package *domain.Package
	Version *domain.PackageVersion
	Item    *domain.RequestItem
	Request *domain.ModerationRequest

	Config Config
	Deps   Deps
	BL     BlacklistPolicy
	Lic    LicensePolicy

	// SecurityOverride — DevSecOps уже разрешил публикацию этой версии.
	// Проверяется runner'ом ОДИН раз перед группой шагов сканирования, а не
	// каждым шагом по отдельности (в Python-версии это продублировано трижды —
	// отмеченный технический долг, который перенос как раз и исправляет).
	SecurityOverride *Override

	// Кеш на один прогон: метаданные реестра запрашиваются один раз, артефакт
	// не перекачивается между шагами сканирования.
	metadata *registry.Metadata
	payload  []byte
	plugin   registry.Plugin
}

// Override — вынесенное решение DevSecOps.
type Override struct {
	DecidedBy string
	DecidedAt time.Time
	Comment   string
}

func (c *Context) now() time.Time {
	if c.Deps.Now != nil {
		return c.Deps.Now()
	}
	return time.Now().UTC()
}

// Ref — ссылка на пакет для плагина менеджера.
func (c *Context) Ref() registry.Ref {
	return registry.Ref{
		Manager:     c.Package.Manager,
		Name:        c.Package.Name,
		DisplayName: c.Package.DisplayName,
		Version:     c.Version.Version,
		RawVersion:  c.Version.RawVersion,
	}
}

// Label — человеческая запись пакета для сообщений.
func (c *Context) Label() string {
	return c.Package.DisplayName + " " + c.Version.RawVersion
}

// Plugin — плагин менеджера этого пакета.
func (c *Context) Plugin() (registry.Plugin, error) {
	if c.plugin != nil {
		return c.plugin, nil
	}
	if c.Deps.Registry == nil {
		return nil, fmt.Errorf("реестр плагинов не настроен")
	}
	plugin, err := c.Deps.Registry.Get(c.Package.Manager)
	if err != nil {
		return nil, err
	}
	c.plugin = plugin
	return plugin, nil
}

// Metadata — метаданные реестра, запрашиваются один раз на прогон конвейера.
func (c *Context) Metadata(ctx context.Context) (registry.Metadata, error) {
	if c.metadata != nil {
		return *c.metadata, nil
	}
	plugin, err := c.Plugin()
	if err != nil {
		return registry.Metadata{}, err
	}
	meta, err := plugin.FetchMetadata(ctx, c.Ref())
	if err != nil {
		return registry.Metadata{}, err
	}
	c.metadata = &meta
	return meta, nil
}

// Payload — байты артефакта. Между шагами сканирования артефакт не
// перекачивается: он уже в памяти после шага скачивания, а если прогон
// возобновлён с более позднего шага — читается из карантинной зоны.
func (c *Context) Payload(ctx context.Context, artifact *domain.Artifact) ([]byte, error) {
	if c.payload != nil {
		return c.payload, nil
	}
	if artifact == nil || artifact.S3Key == nil || *artifact.S3Key == "" {
		return nil, fmt.Errorf("артефакт отсутствует во временном хранилище")
	}
	data, err := c.Deps.Storage.Get(ctx, *artifact.S3Key)
	if err != nil {
		return nil, fmt.Errorf("чтение артефакта из временного хранилища: %w", err)
	}
	c.payload = data
	return data, nil
}

// SetPayload кладёт свежескачанные байты в кеш прогона.
func (c *Context) SetPayload(data []byte) { c.payload = data }

// DropPayload освобождает кеш: после публикации или отклонения держать
// артефакт в памяти незачем, а он бывает в сотни мегабайт.
func (c *Context) DropPayload() { c.payload = nil }
