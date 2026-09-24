package registry

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// groupId и artifactId Maven: буквы, цифры, дефис, подчёркивание, точка.
	mavenCoordRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	mavenVersionR = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// Maven — плагин менеджера maven. Формат записи: groupId:artifactId:version.
//
// Двоеточие, а не «@», потому что так координату пишут везде, где её вообще
// пишут: в pom.xml, в build.gradle, в выводе самого mvn. Просить разработчика
// переписать привычную строку в другой формат — верный способ получить
// опечатку.
type Maven struct {
	// BaseURL — репозитории артефактов через запятую (Maven Central,
	// Google Maven или внутренние зеркала). Maven не имеет единого реестра:
	// например, AndroidX публикуется в Google Maven и отсутствует в Central.
	BaseURL string
	// SearchURL — поисковый API Sonatype: только он отдаёт дату публикации.
	// Пустой — дата не запрашивается, карантин пропускается с пометкой.
	SearchURL string
	HTTP      Doer
}

func (*Maven) Code() string         { return "maven" }
func (*Maven) Title() string        { return "Maven (Java)" }
func (*Maven) EntryFormat() string  { return "groupId:artifactId:version" }
func (*Maven) OSVEcosystem() string { return "Maven" }

// NormalizeName — регистр значим: Maven различает com.Foo и com.foo, и
// приведение к нижнему регистру склеило бы разные пакеты в один.
func (*Maven) NormalizeName(name string) string { return strings.TrimSpace(name) }
func (*Maven) NormalizeVersion(v string) string { return strings.TrimSpace(v) }
func (*Maven) DisplayName(name string) string   { return strings.TrimSpace(name) }
func (*Maven) DependencyFiles() []string {
	return []string{"pom.xml", "build.gradle", "build.gradle.kts"}
}

// SplitEntry разбирает «groupId:artifactId:version».
func (p *Maven) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	parts := strings.Split(text, ":")
	if len(parts) != 3 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату maven. Ожидается: groupId:artifactId:version "+
				"(например, com.google.guava:guava:33.0.0-jre)", text)
	}
	group, artifact, version := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	// Имя пакета — «group:artifact»: уникален пакет именно парой, и хранить их
	// раздельно негде — в схеме одно поле имени.
	return group + ":" + artifact, version, nil
}

func (p *Maven) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Координата длиннее 512 символов")
	}
	group, artifact, ok := splitMavenName(name)
	if !ok {
		return invalidFormat(p.EntryFormat(),
			"«%s» не похоже на координату maven: ожидается groupId:artifactId", name)
	}
	for label, part := range map[string]string{"groupId": group, "artifactId": artifact} {
		if !mavenCoordRe.MatchString(part) {
			return invalidFormat(p.EntryFormat(),
				"Недопустимый %s: «%s» (буквы, цифры, «.», «-», «_»)", label, part)
		}
	}
	return nil
}

func (p *Maven) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !mavenVersionR.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату maven (например, 33.0.0-jre, 2.15.2)", version)
	}
	// SNAPSHOT — версия, которая меняется под тем же именем. Промодерировать
	// её невозможно: завтра по тому же адресу будут другие байты, и решение,
	// принятое сегодня, будет относиться не к ним.
	if strings.HasSuffix(strings.ToUpper(version), "-SNAPSHOT") {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» — SNAPSHOT: её содержимое меняется под тем же именем, "+
				"и решение по ней завтра будет относиться к другим байтам. "+
				"Укажите выпущенную версию", version)
	}
	return nil
}

func splitMavenName(name string) (group, artifact string, ok bool) {
	parts := strings.Split(strings.TrimSpace(name), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// groupPath — groupId в виде пути: com.google.guava → com/google/guava.
func groupPath(group string) string { return strings.ReplaceAll(group, ".", "/") }

// mavenPOM — то, что нам нужно из pom.xml: лицензии.
type mavenPOM struct {
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Licenses struct {
		License []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"license"`
	} `xml:"licenses"`
}

// mavenSearch — ответ поискового API Sonatype.
type mavenSearch struct {
	Response struct {
		Docs []struct {
			// Timestamp — миллисекунды эпохи.
			Timestamp int64 `json:"timestamp"`
		} `json:"docs"`
	} `json:"response"`
}

func (p *Maven) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	group, artifact, ok := splitMavenName(ref.Name)
	if !ok {
		return Metadata{}, invalidFormat(p.EntryFormat(),
			"«%s» не похоже на координату maven", ref.Name)
	}
	filename := fmt.Sprintf("%s-%s.jar", artifact, ref.Version)

	// POM обязателен: по нему проверяется существование версии и берётся
	// лицензия. Один заблокированный CDN не должен мешать проверить следующее
	// зеркало; если все источники ответили 404, это именно ErrNotFound.
	pomBody, base, err := p.fetchPOM(ctx, group, artifact, ref.Version)
	if errors.Is(err, ErrNotFound) {
		return Metadata{}, fmt.Errorf("%w: пакет %s:%s отсутствует в реестре maven (проверены все адреса)",
			ErrNotFound, ref.DisplayName, ref.RawVersion)
	}
	if err != nil {
		return Metadata{}, err
	}

	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      base + "/" + filename,
		ArtifactFilename: filename,
	}
	var pom mavenPOM
	if err := xml.Unmarshal(pomBody, &pom); err == nil {
		meta.LicenseRaw, meta.LicenseSPDX = p.resolvePOMLicenses(ctx, pom,
			map[string]bool{mavenKey(group, artifact, ref.Version): true}, 0)
	}
	// Ошибку разбора POM не поднимаем: лицензия — не условие существования
	// пакета, и сломанный POM отправит пакет к юристу, а не завалит заявку.

	// sha1 лежит рядом с артефактом. Реестр maven не отдаёт контрольную сумму
	// в метаданных — только отдельным файлом.
	if sha1Body, err := getBytes(ctx, p.HTTP, meta.ArtifactURL+".sha1", "text/plain"); err == nil {
		if sum := firstToken(string(sha1Body)); len(sum) == 40 {
			meta.Checksum, meta.ChecksumAlgo = sum, "sha1"
		}
	}

	meta.PublishedAt = p.publishedAt(ctx, group, artifact, ref.Version)
	return meta, nil
}

const mavenMaxParentDepth = 6

func mavenKey(group, artifact, version string) string {
	return group + ":" + artifact + ":" + version
}

// fetchPOM пробует все настроенные репозитории. 404 означает отсутствие в
// конкретном source, а 429/5xx/сетевая ошибка — временную недоступность этого
// source; в обоих случаях следующий источник всё ещё может ответить.
func (p *Maven) fetchPOM(ctx context.Context, group, artifact, version string) ([]byte, string, error) {
	var lastErr error
	var attempts []string
	for _, registryURL := range mavenBaseURLs(p.BaseURL) {
		base := fmt.Sprintf("%s/%s/%s/%s", registryURL, groupPath(group), artifact, version)
		url := fmt.Sprintf("%s/%s-%s.pom", base, artifact, version)
		body, err := getBytes(ctx, p.HTTP, url, "application/xml")
		if err == nil {
			return body, base, nil
		}
		if errors.Is(err, ErrNotFound) {
			attempts = append(attempts, registryURL+"=404")
			continue
		}
		lastErr = err
		attempts = append(attempts, registryURL+"="+err.Error())
	}
	if lastErr != nil {
		return nil, "", fmt.Errorf("Maven POM %s недоступен во всех источниках (%s): %w",
			mavenKey(group, artifact, version), strings.Join(attempts, "; "), lastErr)
	}
	return nil, "", ErrNotFound
}

func mavenLicenseCandidates(pom mavenPOM) []string {
	var candidates []string
	for _, license := range pom.Licenses.License {
		if name := strings.TrimSpace(license.Name); name != "" {
			candidates = append(candidates, name)
		}
		if url := strings.TrimSpace(license.URL); url != "" {
			candidates = append(candidates, url)
		}
	}
	return candidates
}

// resolvePOMLicenses поднимается по parent POM, если дочерний POM не объявил
// распознаваемую лицензию. Так устроены многие Spring, Hibernate и Gradle
// артефакты. Ошибка parent не валит существующий пакет — его разберёт юрист.
func (p *Maven) resolvePOMLicenses(ctx context.Context, pom mavenPOM,
	visited map[string]bool, depth int) (raw, spdx string) {
	candidates := mavenLicenseCandidates(pom)
	raw, spdx = normalizeLicenseCandidates(candidates)
	if spdx != "" || depth >= mavenMaxParentDepth {
		return raw, spdx
	}
	group := strings.TrimSpace(pom.Parent.GroupID)
	artifact := strings.TrimSpace(pom.Parent.ArtifactID)
	version := strings.TrimSpace(pom.Parent.Version)
	if group == "" || artifact == "" || version == "" ||
		strings.Contains(group+artifact+version, "${") {
		return raw, spdx
	}
	key := mavenKey(group, artifact, version)
	if visited[key] {
		return raw, spdx
	}
	visited[key] = true
	body, _, err := p.fetchPOM(ctx, group, artifact, version)
	if err != nil {
		return raw, spdx
	}
	var parent mavenPOM
	if xml.Unmarshal(body, &parent) != nil {
		return raw, spdx
	}
	parentRaw, parentSPDX := p.resolvePOMLicenses(ctx, parent, visited, depth+1)
	if parentSPDX != "" {
		return parentRaw, parentSPDX
	}
	if raw == "" {
		raw = parentRaw
	}
	return raw, ""
}

// mavenBaseURLs разбирает список репозиториев. Запятая выбрана потому, что
// URL Maven не содержит её, а значение остаётся совместимым с прежней
// настройкой из одного адреса.
func mavenBaseURLs(value string) []string {
	var urls []string
	for _, raw := range strings.Split(value, ",") {
		if url := strings.TrimRight(strings.TrimSpace(raw), "/"); url != "" {
			urls = append(urls, url)
		}
	}
	return urls
}

// publishedAt — дата публикации из поискового API. nil, если узнать не
// удалось: неизвестная дата означает «карантин пропущен с пометкой», и врать
// про неё нулевым временем нельзя — тогда карантин молча считался бы пройденным.
func (p *Maven) publishedAt(ctx context.Context, group, artifact, version string) *time.Time {
	if strings.TrimSpace(p.SearchURL) == "" {
		return nil
	}
	url := fmt.Sprintf(`%s/solrsearch/select?q=g:%%22%s%%22+AND+a:%%22%s%%22+AND+v:%%22%s%%22&rows=1&wt=json`,
		strings.TrimRight(p.SearchURL, "/"), group, artifact, version)
	var found mavenSearch
	if err := getJSON(ctx, p.HTTP, url, "application/json", &found); err != nil {
		return nil
	}
	if len(found.Response.Docs) == 0 || found.Response.Docs[0].Timestamp <= 0 {
		return nil
	}
	published := time.UnixMilli(found.Response.Docs[0].Timestamp).UTC()
	return &published
}

func (p *Maven) InstallCommand(ref Ref, baseURL, repo string) string {
	group, artifact, _ := splitMavenName(ref.Name)
	return fmt.Sprintf(
		"добавьте репозиторий %s/repository/%s в pom.xml и зависимость "+
			"<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>",
		strings.TrimRight(baseURL, "/"), repo, group, artifact, ref.RawVersion)
}

func (p *Maven) ArtifactPath(ref Ref, filename string) string {
	group, artifact, ok := splitMavenName(ref.Name)
	if !ok {
		return filename
	}
	// Раскладка Maven обязана быть именно такой: по ней артефакт ищет сам
	// mvn, и «положить куда-нибудь» означает «репозиторий не работает».
	return fmt.Sprintf("%s/%s/%s/%s", groupPath(group), artifact, ref.Version, filename)
}

// firstToken — первое слово строки. Файлы контрольных сумм в maven бывают и
// «<сумма>», и «<сумма>  <имя файла>».
func firstToken(text string) string {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
