// Порт backend/app/db/models.py — доменные структуры. Отличие от Python-версии:
// JSON-поля здесь типизированы нативно (не map[string]any как в SQLAlchemy JSON),
// в БД лежат как JSONB (см. migrations/0001, комментарий про отказ от
// SQLite-совместимости). Slice-поля вида Roles/Warnings/Mentions нигде не equal
// nil в базе — пустой список хранится как `[]`, не NULL (сохраняем поведение
// Python default=list).
package domain

import "time"

type User struct {
	ID        int64
	Subject   *string // sub из OIDC
	Username  string
	Email     *string
	FullName  *string
	Roles     []string
	IsService bool
	IsActive  bool

	PasswordHash *string
	LastLoginAt  *time.Time

	// GitLab (только чтение репозиториев); токены зашифрованы Fernet-аналогом
	// и не отдаются в API.
	GitlabUsername        *string
	GitlabAccessTokenEnc  *string
	GitlabRefreshTokenEnc *string
	GitlabTokenExpiresAt  *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasRole — порт User.has_role из Python-версии.
func (u User) HasRole(roles ...string) bool {
	for _, r := range roles {
		if Contains(u.Roles, r) {
			return true
		}
	}
	return false
}

// DisplayName — порт User.display_name.
func (u User) DisplayName() string {
	if u.FullName != nil && *u.FullName != "" {
		return *u.FullName
	}
	return u.Username
}

type PackageManager struct {
	ID          int64
	Code        string
	Title       string
	EntryFormat string
	Enabled     bool
}

type Package struct {
	ID                      int64
	Manager                 string
	Name                    string // нормализованное имя
	DisplayName             string // как заявил разработчик
	ConfirmedLicenseSPDX    *string
	ConfirmedLicenseVersion *string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type PackageVersion struct {
	ID         int64
	PackageID  int64
	Version    string // нормализованная
	RawVersion string
	Status     string

	PublishedAt      *time.Time
	QuarantineUntil  *time.Time
	LicenseSPDX      *string
	LicenseSource    *string // registry | claim | manual
	LicenseRaw       *string
	RegistryMetadata map[string]any // JSONB

	VulnIndexVersionID *int64
	MaxVulnScore       *float64

	// Явное решение DevSecOps «публиковать несмотря на результат шага 5» —
	// без него возобновление конвейера снова упиралось бы в тот же вердикт.
	// Проверяется централизованно в pipeline runner (см. docs/architecture.md
	// про технический долг Python-версии — там проверка продублирована в трёх
	// шагах, здесь так не делать).
	SecurityOverrideAt      *time.Time
	SecurityOverrideByID    *int64
	SecurityOverrideComment *string

	ApprovedAt   *time.Time
	RevokedAt    *time.Time
	StatusReason *string

	CreatedAt time.Time
	UpdatedAt time.Time
}

type ModerationRequest struct {
	ID                int64
	AuthorID          int64
	AuthorRole        *string
	Manager           string
	Reason            *string
	Status            string
	Source            string
	IdempotencyKey    *string
	OriginFile        *string
	IncludeTransitive bool
	Warnings          []string // JSONB

	CreatedAt time.Time
	UpdatedAt time.Time
}

type RequestItem struct {
	ID               int64
	RequestID        int64
	PackageVersionID int64
	RequestedName    string
	RequestedVersion string
	DependencyKind   string
	Status           string
	CurrentStep      *string
	NextAction       *string // блок «Что делать» для разработчика
	BlockedReason    *string
	WaitingSince     *time.Time
	FinishedAt       *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// PipelineStep — шаг конвейера с результатом, объяснением и временем.
type PipelineStep struct {
	ID            int64
	RequestItemID int64
	StepCode      string
	StepOrder     int
	Result        string
	Message       *string
	Details       map[string]any // JSONB
	StartedAt     *time.Time
	FinishedAt    *time.Time
}

// VulnIndexVersion — версия снапшота базы OSV, по которой вынесено решение.
type VulnIndexVersion struct {
	ID           int64
	Version      string
	Source       string
	Checksum     *string
	RemotePath   *string
	LocalPath    *string
	PublishedAt  *time.Time
	DownloadedAt *time.Time
	RecordCount  *int
	IsActive     bool
}

type Vulnerability struct {
	ID                 int64
	PackageVersionID   int64
	ExternalID         string // CVE / GHSA
	Aliases            []string
	Summary            *string
	CVSSVector         *string
	CVSSScore          *float64
	Score              float64 // 0..100
	Severity           *string
	URL                *string
	AffectedRanges     []map[string]any
	FixedVersions      []string
	VulnIndexVersionID *int64
	DetectedAt         *time.Time
}

// CodeFinding — находка сканера содержимого пакета: политический баннер или
// SAST. Отдельно от Vulnerability: там уязвимости из базы OSV со своей
// нумерацией и баллом CVSS, здесь — срабатывание правила по исходникам с
// файлом и строкой.
type CodeFinding struct {
	ID               int64
	PackageVersionID int64
	Scanner          string // yara | semgrep
	RuleID           string
	Severity         string
	Message          *string
	FilePath         *string
	Line             *int
	Matched          *string
	DetectedAt       *time.Time
}

// License — справочник SPDX: какие лицензии разрешены.
type License struct {
	ID      int64
	SPDXID  string
	Name    *string
	Allowed bool
	URL     *string
	Notes   *string
}

// LicenseClaim — заявление лицензии разработчиком для пакета, остановленного
// на шаге "license".
type LicenseClaim struct {
	ID                int64
	PackageVersionID  int64
	RequestItemID     *int64
	ClaimedByID       int64
	URL               string
	SnapshotText      *string
	SnapshotFetchedAt *time.Time
	SPDXID            *string
	Comment           *string
	Status            string
	DecidedByID       *int64
	DecidedAt         *time.Time
	DecisionComment   *string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Comment — обсуждение: ветка на заявку целиком (RequestItemID == nil) и на
// каждый её пакет (RequestItemID != nil).
type Comment struct {
	ID            int64
	RequestID     int64
	RequestItemID *int64
	AuthorID      int64
	AuthorRole    *string
	Body          string // markdown
	Mentions      []string
	IsEdited      bool
	EditedAt      *time.Time
	DeletedAt     *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Artifact — ключ в S3-хранилище (временно, карантинная зона) и URL в
// артефактори (постоянно).
type Artifact struct {
	ID               int64
	PackageVersionID int64
	Filename         string
	SourceURL        *string
	SizeBytes        *int64
	SHA256           *string
	DeclaredChecksum *string
	ChecksumAlgo     *string
	S3Bucket         *string
	S3Key            *string
	S3UploadedAt     *time.Time
	S3DeletedAt      *time.Time
	NexusURL         *string
	PublishedAt      *time.Time
	Status           string
}

type Notification struct {
	ID            int64
	UserID        int64
	Event         string
	Title         string
	Body          *string
	RequestID     *int64
	RequestItemID *int64
	Payload       map[string]any
	CreatedAt     time.Time
	ReadAt        *time.Time
}

// AuditLog — кто, что, когда, старое/новое значение, источник (UI / REST API /
// фоновая задача / CLI).
type AuditLog struct {
	ID         int64
	ActorID    *int64
	ActorName  string
	ActorRole  *string
	Action     string
	EntityType string
	EntityID   *string
	OldValue   map[string]any
	NewValue   map[string]any
	Source     string
	RequestID  *string // correlation id
	IP         *string
	Comment    *string
	CreatedAt  time.Time
}
