package registry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Git описывает заявку на зеркалирование репозитория целиком. В отличие от
// пакетных менеджеров у неё нет отдельной версии: worker переносит все ветки,
// теги и LFS-объекты, а защищённая рабочая копия живёт в pt/*.
type Git struct{}

func (*Git) Code() string              { return "git" }
func (*Git) Title() string             { return "Git-репозитории" }
func (*Git) EntryFormat() string       { return "https://host/group/project[.git]" }
func (*Git) OSVEcosystem() string      { return "" }
func (*Git) DependencyFiles() []string { return nil }

func (*Git) NormalizeName(name string) string {
	return strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(name), "/"), ".git")
}

// Служебная версия одна: повторная заявка синхронизирует тот же проект, а не
// создаёт новую строку на каждую ветку. Реальные revisions остаются в GitLab.
func (*Git) NormalizeVersion(string) string { return "mirror" }
func (*Git) DisplayName(name string) string { return strings.TrimSpace(name) }

func (p *Git) SplitEntry(entry string) (string, string, error) {
	value := strings.TrimSpace(entry)
	// Старый интерфейс принимал URL@ref. Оставляем совместимость ввода, но ref
	// больше не ограничивает зеркало: переносится репозиторий целиком.
	if at := strings.LastIndex(value, "@"); at > strings.LastIndex(value, "/") {
		value = strings.TrimSpace(value[:at])
	}
	return value, "mirror", nil
}

func (p *Git) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Адрес репозитория длиннее 512 символов")
	}
	u, err := url.Parse(strings.TrimSpace(name))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return invalidFormat(p.EntryFormat(),
			"Ожидается полный адрес Git-репозитория http(s)://host/group/project")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return invalidFormat(p.EntryFormat(),
			"Адрес Git-репозитория не должен содержать учётные данные, query или fragment")
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if len(strings.Split(path, "/")) < 2 {
		return invalidFormat(p.EntryFormat(), "В адресе должны быть группа и проект")
	}
	return nil
}

func (p *Git) ValidateVersion(version string) error {
	if version != "mirror" {
		return invalidFormat(p.EntryFormat(), "Git-модерация принимает URL репозитория без версии")
	}
	return nil
}

func (*Git) FetchMetadata(_ context.Context, ref Ref) (Metadata, error) {
	return Metadata{
		Name: ref.Name, Version: ref.Version, ArtifactURL: ref.DisplayName,
		ArtifactFilename: "repository.git",
	}, nil
}

// Готовая команда формируется по URL опубликованного проекта в API карточки.
// Здесь базовый адрес артефактори неприменим.
func (*Git) InstallCommand(Ref, string, string) string { return "" }

func (*Git) ArtifactPath(ref Ref, _ string) string {
	u, err := url.Parse(ref.Name)
	if err != nil {
		return "repository.git"
	}
	return fmt.Sprintf("%s/%s", strings.ToLower(u.Hostname()),
		strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"))
}
