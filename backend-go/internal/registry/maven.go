package registry

import (
	"context"
	"encoding/xml"
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
	// BaseURL — репозиторий артефактов (Maven Central или внутреннее зеркало).
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
	base := fmt.Sprintf("%s/%s/%s/%s", strings.TrimRight(p.BaseURL, "/"),
		groupPath(group), artifact, ref.Version)
	filename := fmt.Sprintf("%s-%s.jar", artifact, ref.Version)

	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      base + "/" + filename,
		ArtifactFilename: filename,
	}

	// POM обязателен: по нему проверяется само существование версии и
	// берётся лицензия. Его отсутствие — это «такой версии нет», а не
	// «лицензия не указана».
	pomBody, err := getBytes(ctx, p.HTTP, fmt.Sprintf("%s/%s-%s.pom", base, artifact, ref.Version),
		"application/xml")
	if err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: пакет %s:%s отсутствует в реестре maven",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return Metadata{}, err
	}
	var pom mavenPOM
	if err := xml.Unmarshal(pomBody, &pom); err == nil && len(pom.Licenses.License) > 0 {
		meta.LicenseRaw = pom.Licenses.License[0].Name
		if meta.LicenseRaw == "" {
			meta.LicenseRaw = pom.Licenses.License[0].URL
		}
		meta.LicenseSPDX = NormalizeSPDX(meta.LicenseRaw)
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
