// Package registry — плагины пакетных менеджеров: нормализация имени и версии,
// разбор записи заявки, клиент реестра и правила публикации в артефактори.
//
// Порт backend/app/managers/. Реализованы все двенадцать менеджеров: четыре из
// прототипа (pypi, npm, go, nuget) и восемь добавленных — maven, docker, conan,
// luarocks, terraform, php, git, files.
//
// Два последних устроены иначе остальных, и это не недоработка, а природа
// предмета: у git-репозитория и у принесённого файла нет реестра, у которого
// можно спросить метаданные, и нет версии в привычном смысле. Как именно они
// с этим обходятся — в git.go и files.go.
//
// Два (docker и git) реализуют Downloader: их артефакт не лежит по ссылке
// одним файлом, его надо собрать. См. download.go.
//
// Разбор файлов зависимостей (requirements.txt, go.sum, packages.lock.json и
// прочие) в этой ревизии сознательно не перенесён: конвейеру он не нужен, а
// нужен API создания заявки — он переносится отдельной фазой. Интерфейс
// оставлен без метода parse_dependency_file, чтобы не заводить заглушек,
// которые молча возвращают пустой список.
package registry

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotFound — версии нет в реестре. Отличается от «реестр недоступен»:
// первое — ошибка пользователя (опечатка в версии), второе — повод повторить.
var ErrNotFound = errors.New("версия не найдена в реестре")

// InvalidFormatError — запись не соответствует формату менеджера. Несёт
// ожидаемый формат: сообщение «ожидается name==version» полезнее, чем «неверный
// формат», и уходит прямо в интерфейс.
type InvalidFormatError struct {
	Message        string
	ExpectedFormat string
}

func (e *InvalidFormatError) Error() string { return e.Message }

func invalidFormat(expected, format string, args ...any) error {
	return &InvalidFormatError{Message: fmt.Sprintf(format, args...), ExpectedFormat: expected}
}

// Ref — разобранная ссылка на пакет конкретной версии.
type Ref struct {
	Manager     string
	Name        string // нормализованное имя (для уникальности и поиска)
	DisplayName string // как записал разработчик
	Version     string // нормализованная версия
	RawVersion  string
}

// Entry — человеческая запись пакета, как её видно в заявке.
func (r Ref) Entry() string { return r.DisplayName + "@" + r.RawVersion }

// Metadata — метаданные версии из реестра пакетного менеджера.
type Metadata struct {
	Name             string
	Version          string
	PublishedAt      *time.Time
	LicenseSPDX      string
	LicenseRaw       string
	ArtifactURL      string
	ArtifactFilename string
	Checksum         string
	ChecksumAlgo     string
	SizeBytes        int64
	Yanked           bool
}

// Plugin — контракт менеджера.
type Plugin interface {
	Code() string
	Title() string
	EntryFormat() string

	// NormalizeName приводит имя к виду, по которому пакет уникален.
	NormalizeName(name string) string
	// NormalizeVersion приводит версию к каноническому виду менеджера.
	NormalizeVersion(version string) string
	// DisplayName — имя в том виде, как его записал разработчик.
	DisplayName(name string) string

	// SplitEntry разбивает строку записи на имя и версию.
	SplitEntry(entry string) (name, version string, err error)
	// ValidateName и ValidateVersion проверяют формат до обращения к реестру:
	// опечатку возвращаем сразу, а не через таймаут походом наружу.
	ValidateName(name string) error
	ValidateVersion(version string) error

	// FetchMetadata — метаданные версии: дата публикации, лицензия, URL
	// артефакта и хеш.
	FetchMetadata(ctx context.Context, ref Ref) (Metadata, error)

	// InstallCommand — готовая команда установки из внутреннего репозитория.
	InstallCommand(ref Ref, baseURL, repo string) string
	// ArtifactPath — путь артефакта внутри репозитория артефактори.
	ArtifactPath(ref Ref, filename string) string
	// OSVEcosystem — имя экосистемы в базе OSV.
	OSVEcosystem() string
	// DependencyFiles — имена файлов зависимостей менеджера, шаблонами в
	// синтаксисе glob. По ним интерфейс подсказывает менеджер по
	// перетащенному файлу.
	DependencyFiles() []string
}

// MakeRef собирает Ref, прогоняя имя и версию через валидацию плагина.
func MakeRef(p Plugin, name, version string) (Ref, error) {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" {
		return Ref{}, invalidFormat(p.EntryFormat(),
			"Не указано имя пакета. Ожидаемый формат: %s", p.EntryFormat())
	}
	if version == "" {
		return Ref{}, invalidFormat(p.EntryFormat(),
			"Не указана версия пакета «%s». Ожидаемый формат: %s", name, p.EntryFormat())
	}
	if err := p.ValidateName(name); err != nil {
		return Ref{}, err
	}
	if err := p.ValidateVersion(version); err != nil {
		return Ref{}, err
	}
	return Ref{
		Manager:     p.Code(),
		Name:        p.NormalizeName(name),
		DisplayName: p.DisplayName(name),
		Version:     p.NormalizeVersion(version),
		RawVersion:  version,
	}, nil
}

// ParseEntry разбирает строку вида «имя<разделитель>версия».
func ParseEntry(p Plugin, entry string) (Ref, error) {
	name, version, err := p.SplitEntry(entry)
	if err != nil {
		return Ref{}, err
	}
	return MakeRef(p, name, version)
}

// --------------------------------------------------------------------------- реестр плагинов

// Registry — набор доступных менеджеров.
type Registry struct {
	plugins map[string]Plugin
	// order — порядок плагинов как их объявили. Отдельно от карты: порядок
	// виден пользователю в выпадающем списке менеджеров, а обход map в Go
	// намеренно случаен — список прыгал бы от запроса к запросу.
	order []Plugin
}

// Config — адреса реестров. Пустое значение заменяется публичным адресом по
// умолчанию; в бою сюда подставляются внутренние зеркала.
type Config struct {
	PyPIURL      string
	NpmURL       string
	GoProxy      string
	GoLicenseURL string
	NuGetURL     string

	MavenURL       string
	MavenSearchURL string
	DockerURL      string
	DockerAuthURL  string
	DockerService  string
	ConanURL       string
	LuaRocksURL    string
	TerraformURL   string
	PackagistURL   string

	// GitBinary — исполняемый файл git для менеджера git. Пусто — «git» из PATH.
	GitBinary string
	// GitTimeout — потолок на одно клонирование.
	GitTimeout time.Duration

	// HTTP — клиент для походов в реестры. Обязателен: он несёт таймауты,
	// повторы и корпоративный прокси.
	HTTP Doer
}

// New собирает реестр плагинов.
func New(cfg Config) *Registry {
	if cfg.PyPIURL == "" {
		cfg.PyPIURL = "https://pypi.org"
	}
	if cfg.NpmURL == "" {
		cfg.NpmURL = "https://registry.npmjs.org"
	}
	if cfg.GoProxy == "" {
		cfg.GoProxy = "https://proxy.golang.org"
	}
	if cfg.GoLicenseURL == "" {
		cfg.GoLicenseURL = "https://pkg.go.dev"
	}
	if cfg.NuGetURL == "" {
		cfg.NuGetURL = "https://api.nuget.org"
	}
	// Адреса по умолчанию — публичные реестры. В бою сюда подставляются
	// внутренние зеркала; пустое значение здесь означало бы плагин, который
	// собирает запросы к «/v2/...» без хоста и падает на первом же пакете.
	defaults := map[*string]string{
		&cfg.MavenURL: "https://repo.maven.apache.org/maven2,https://repo1.maven.org/maven2," +
			"https://dl.google.com/dl/android/maven2,https://repo.clojars.org,https://plugins.gradle.org/m2",
		&cfg.MavenSearchURL: "https://search.maven.org",
		&cfg.DockerURL:      "https://registry-1.docker.io",
		&cfg.DockerAuthURL:  "https://auth.docker.io/token",
		&cfg.DockerService:  "registry.docker.io",
		&cfg.ConanURL:       "https://center2.conan.io",
		&cfg.LuaRocksURL:    "https://luarocks.org",
		&cfg.TerraformURL:   "https://registry.terraform.io",
		&cfg.PackagistURL:   "https://repo.packagist.org",
	}
	for field, value := range defaults {
		if strings.TrimSpace(*field) == "" {
			*field = value
		}
	}

	// Порядок объявления виден пользователю в выпадающем списке менеджеров —
	// он тот же, что в domain.ManagerCodes: сначала четыре самых ходовых,
	// затем остальные по алфавиту, и последними два «не из реестра».
	plugins := []Plugin{
		&PyPI{BaseURL: strings.TrimRight(cfg.PyPIURL, "/"), HTTP: cfg.HTTP},
		&Npm{BaseURL: strings.TrimRight(cfg.NpmURL, "/"), HTTP: cfg.HTTP},
		&Go{
			BaseURL:    strings.TrimRight(cfg.GoProxy, "/"),
			LicenseURL: strings.TrimRight(cfg.GoLicenseURL, "/"), HTTP: cfg.HTTP,
		},
		&NuGet{BaseURL: strings.TrimRight(cfg.NuGetURL, "/"), HTTP: cfg.HTTP},

		&Conan{BaseURL: strings.TrimRight(cfg.ConanURL, "/"), HTTP: cfg.HTTP},
		&Docker{
			BaseURL: strings.TrimRight(cfg.DockerURL, "/"),
			AuthURL: cfg.DockerAuthURL, Service: cfg.DockerService,
			DefaultNamespace: "library", HTTP: cfg.HTTP,
		},
		&LuaRocks{BaseURL: strings.TrimRight(cfg.LuaRocksURL, "/"), HTTP: cfg.HTTP},
		&Maven{
			BaseURL:   strings.TrimRight(cfg.MavenURL, "/"),
			SearchURL: strings.TrimRight(cfg.MavenSearchURL, "/"),
			HTTP:      cfg.HTTP,
		},
		&PHP{BaseURL: strings.TrimRight(cfg.PackagistURL, "/"), HTTP: cfg.HTTP},
		&Terraform{
			BaseURL: strings.TrimRight(cfg.TerraformURL, "/"),
			HTTP:    cfg.HTTP, DefaultPlatform: "linux_amd64",
		},

		&Git{Binary: cfg.GitBinary, Timeout: cfg.GitTimeout},
		&Files{},
	}
	r := &Registry{plugins: make(map[string]Plugin, len(plugins)), order: plugins}
	for _, p := range plugins {
		r.plugins[p.Code()] = p
	}
	return r
}

// Plugins — все плагины в порядке объявления (тот же, что у python-версии:
// pypi, npm, go, nuget).
func (r *Registry) Plugins() []Plugin {
	out := make([]Plugin, len(r.order))
	copy(out, r.order)
	return out
}

// DetectByFile — менеджер по имени файла зависимостей. Пустая строка, если
// файл ничей. Порт registry.detect_manager_by_file.
//
// Сравнивается только базовое имя: пользователь перетаскивает файл, и путь к
// нему на его машине к делу не относится.
func (r *Registry) DetectByFile(filename string) string {
	base := path.Base(filepath.ToSlash(strings.TrimSpace(filename)))
	if base == "." || base == "/" || base == "" {
		return ""
	}
	for _, p := range r.order {
		for _, pattern := range p.DependencyFiles() {
			// Ошибка шаблона означает опечатку в самом плагине, а не в
			// пользовательском вводе; такой шаблон просто не совпадает ни с чем.
			if ok, err := path.Match(pattern, base); err == nil && ok {
				return p.Code()
			}
		}
	}
	return ""
}

// Get возвращает плагин менеджера.
func (r *Registry) Get(manager string) (Plugin, error) {
	p, ok := r.plugins[strings.ToLower(strings.TrimSpace(manager))]
	if !ok {
		return nil, fmt.Errorf("менеджер пакетов %q не поддерживается", manager)
	}
	return p, nil
}

// Codes — коды поддерживаемых менеджеров, в порядке объявления.
func (r *Registry) Codes() []string {
	out := make([]string, 0, len(r.order))
	for _, p := range r.order {
		out = append(out, p.Code())
	}
	return out
}

// NewWithPlugin возвращает копию реестра с заменённым плагином одного
// менеджера. Нужен тестам конвейера, которым требуется подменить поведение
// одного менеджера, не поднимая фейковый реестр целиком.
func NewWithPlugin(base *Registry, plugin Plugin) *Registry {
	plugins := make(map[string]Plugin, len(base.plugins))
	for code, p := range base.plugins {
		plugins[code] = p
	}
	plugins[plugin.Code()] = plugin
	order := make([]Plugin, len(base.order))
	copy(order, base.order)
	for i, p := range order {
		if p.Code() == plugin.Code() {
			order[i] = plugin
		}
	}
	return &Registry{plugins: plugins, order: order}
}
