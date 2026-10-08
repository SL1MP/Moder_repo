package registry

import (
	"context"
	"crypto/sha1" //nolint:gosec // сверка с опубликованной Maven checksum
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// groupId и artifactId Maven: буквы, цифры, дефис, подчёркивание, точка.
	mavenCoordRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	mavenVersionR = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	mavenHrefRe   = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
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
func (*Maven) OSVEcosystem() string { return "" }

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

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Optional   string `xml:"optional"`
}

// mavenProperties сохраняет произвольные имена из <properties>. У Maven
// имя свойства одновременно является XML-тегом, поэтому обычной struct для
// этого блока недостаточно.
type mavenProperties map[string]string

func (p *mavenProperties) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if *p == nil {
		*p = make(map[string]string)
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			var text string
			if err := decoder.DecodeElement(&text, &value); err != nil {
				return err
			}
			(*p)[value.Name.Local] = strings.TrimSpace(text)
		case xml.EndElement:
			if value.Name == start.Name {
				return nil
			}
		}
	}
}

// mavenPOM — поля pom.xml для лицензий и графа зависимостей.
type mavenPOM struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Properties mavenProperties `xml:"properties"`
	DependencyManagement struct {
		Dependencies []mavenDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []mavenDependency `xml:"dependencies>dependency"`
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

func (*Maven) ReleaseBundle() {}

type gradleModuleMetadata struct {
	Variants []struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	} `json:"variants"`
}

// Download собирает все устанавливаемые ассеты одной Maven-версии. Файлы
// документации, исходников, подписей и checksum не публикуются; checksum при
// наличии используется только для проверки скачанных байтов.
func (p *Maven) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	group, artifact, ok := splitMavenName(ref.Name)
	if !ok {
		return nil, "", invalidFormat(p.EntryFormat(), "некорректная Maven-координата %q", ref.Name)
	}
	pomBody, base, err := p.fetchPOM(ctx, group, artifact, ref.RawVersion)
	if err != nil {
		return nil, "", err
	}
	prefix := artifact + "-" + ref.RawVersion
	pomName := prefix + ".pom"

	// Directory listing нужен для classifier-артефактов, имя которых нельзя
	// вывести заранее: gradle80/gradle81, платформенные protoc-*.exe и т.п.
	listed := map[string]bool{}
	if listing, listErr := getBytes(ctx, p.HTTP, base+"/", "text/html"); listErr == nil {
		for _, name := range mavenListingNames(listing) {
			listed[name] = true
		}
	}

	candidates := map[string]bool{pomName: true}
	for name := range listed {
		if AllowedMavenAsset(name) {
			candidates[name] = true
		}
	}
	// Для репозиториев без listing пробуем стандартные имена. .module затем
	// подскажет дополнительные variant files.
	for _, ext := range []string{"jar", "aar", "klib", "zip", "module"} {
		candidates[prefix+"."+ext] = true
	}

	bodies := map[string][]byte{pomName: pomBody}
	queue := sortedKeys(candidates)
	for cursor := 0; cursor < len(queue); cursor++ {
		name := queue[cursor]
		if _, present := bodies[name]; present {
			continue
		}
		remaining := remainingLimit(limit, bodies)
		if limit > 0 && remaining <= 0 {
			return nil, "", fmt.Errorf("файлы Maven-версии больше допустимого предела %d байт", limit)
		}
		body, fetchErr := getBytesWithLimit(ctx, p.HTTP, base+"/"+url.PathEscape(name),
			"application/octet-stream", remaining)
		if errors.Is(fetchErr, ErrNotFound) {
			// Стандартные имена — пробы; отсутствие конкретного packaging штатно.
			if listed[name] {
				return nil, "", fmt.Errorf("файл %s объявлен Maven-репозиторием, но исчез при скачивании", name)
			}
			continue
		}
		if fetchErr != nil {
			return nil, "", fmt.Errorf("скачивание Maven-файла %s: %w", name, fetchErr)
		}
		bodies[name] = body
		if strings.HasSuffix(strings.ToLower(name), ".module") {
			for _, variant := range mavenModuleFiles(body) {
				if AllowedMavenAsset(variant) && !candidates[variant] {
					candidates[variant] = true
					queue = append(queue, variant)
				}
			}
		}
	}

	files := make([]BundleFile, 0, len(bodies))
	for _, name := range sortedBodyKeys(bodies) {
		body := bodies[name]
		if err := verifyMavenChecksum(ctx, p.HTTP, base, name, body, listed); err != nil {
			return nil, "", err
		}
		files = append(files, BundleFile{Name: name, Data: body})
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("Maven-версия %s:%s не содержит разрешённых артефактов",
			ref.DisplayName, ref.RawVersion)
	}
	bundle, err := PackBundle("maven", files, limit)
	if err != nil {
		return nil, "", err
	}
	return bundle, prefix + ".maven-release.tgz", nil
}

func mavenListingNames(body []byte) []string {
	seen := map[string]bool{}
	var names []string
	for _, match := range mavenHrefRe.FindAllSubmatch(body, -1) {
		raw := html.UnescapeString(string(match[1]))
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") {
			continue
		}
		name, err := url.PathUnescape(path.Base(parsed.Path))
		if err != nil || name == "" || name == "." || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AllowedMavenAsset — единая белая таблица файлов Maven-релиза. Она
// экспортирована намеренно: и скачивание, и последний рубеж перед публикацией
// в Nexus обязаны применять одно правило, чтобы checksum/source/javadoc не
// проскочили из старого staging bundle после обновления сервиса.
func AllowedMavenAsset(name string) bool {
	lower := strings.ToLower(path.Base(strings.TrimSpace(name)))
	if lower == "" || lower != strings.ToLower(strings.TrimSpace(name)) {
		return false
	}
	for _, suffix := range []string{
		"-sources.jar", "-javadoc.jar", ".md5", ".sha1", ".sha256", ".sha512", ".asc",
	} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	switch path.Ext(lower) {
	case ".zip", ".jar", ".pom", ".aar", ".klib", ".module":
		return true
	case ".exe":
		return strings.HasPrefix(lower, "protoc-")
	default:
		return false
	}
}

func mavenModuleFiles(body []byte) []string {
	var module gradleModuleMetadata
	if json.Unmarshal(body, &module) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, variant := range module.Variants {
		for _, file := range variant.Files {
			name := path.Base(strings.TrimSpace(file.Name))
			if name != file.Name || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func verifyMavenChecksum(ctx context.Context, client Doer, base, name string, body []byte, listed map[string]bool) error {
	for _, check := range []struct {
		suffix string
		length int
		actual func([]byte) string
	}{
		{".sha256", 64, func(data []byte) string {
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:])
		}},
		{".sha1", 40, func(data []byte) string {
			sum := sha1.Sum(data) //nolint:gosec // сверка с Maven checksum
			return hex.EncodeToString(sum[:])
		}},
	} {
		checksumName := name + check.suffix
		if !listed[checksumName] {
			continue
		}
		raw, err := getBytes(ctx, client, base+"/"+url.PathEscape(checksumName), "text/plain")
		if err != nil {
			return fmt.Errorf("чтение checksum %s: %w", checksumName, err)
		}
		declared := firstToken(string(raw))
		if len(declared) != check.length || !strings.EqualFold(declared, check.actual(body)) {
			return fmt.Errorf("контрольная сумма Maven-файла %s не совпала (%s)", name, check.suffix[1:])
		}
		return nil
	}
	return nil
}

func remainingLimit(limit int64, bodies map[string][]byte) int64 {
	if limit <= 0 {
		return limit
	}
	remaining := limit
	for _, body := range bodies {
		remaining -= int64(len(body))
	}
	return remaining
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedBodyKeys(values map[string][]byte) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
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
