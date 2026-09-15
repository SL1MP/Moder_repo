// Package registry — плагины пакетных менеджеров: нормализация имени и версии,
// разбор записи заявки, клиент реестра и правила публикации в артефактори.
//
// Порт backend/app/managers/. Перенесены четыре менеджера прототипа
// (pypi, npm, go, nuget). Недостающие шесть (general, maven, terraform,
// luarocks, docker, conan) — обязательный скоуп, не бэклог; порядок и
// обоснование — docs/ci-parity-gaps.md, Docker вне очереди.
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
}

// Config — адреса реестров. Пустое значение заменяется публичным адресом по
// умолчанию; в бою сюда подставляются внутренние зеркала.
type Config struct {
	PyPIURL  string
	NpmURL   string
	GoProxy  string
	NuGetURL string
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
	if cfg.NuGetURL == "" {
		cfg.NuGetURL = "https://api.nuget.org"
	}
	plugins := []Plugin{
		&PyPI{BaseURL: strings.TrimRight(cfg.PyPIURL, "/"), HTTP: cfg.HTTP},
		&Npm{BaseURL: strings.TrimRight(cfg.NpmURL, "/"), HTTP: cfg.HTTP},
		&Go{BaseURL: strings.TrimRight(cfg.GoProxy, "/"), HTTP: cfg.HTTP},
		&NuGet{BaseURL: strings.TrimRight(cfg.NuGetURL, "/"), HTTP: cfg.HTTP},
	}
	r := &Registry{plugins: make(map[string]Plugin, len(plugins))}
	for _, p := range plugins {
		r.plugins[p.Code()] = p
	}
	return r
}

// Get возвращает плагин менеджера.
func (r *Registry) Get(manager string) (Plugin, error) {
	p, ok := r.plugins[strings.ToLower(strings.TrimSpace(manager))]
	if !ok {
		return nil, fmt.Errorf("менеджер пакетов %q не поддерживается", manager)
	}
	return p, nil
}

// Codes — коды поддерживаемых менеджеров.
func (r *Registry) Codes() []string {
	out := make([]string, 0, len(r.plugins))
	for code := range r.plugins {
		out = append(out, code)
	}
	return out
}
