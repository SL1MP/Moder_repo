package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	// Имя образа: [хост/]путь, сегменты — строчные буквы, цифры и разделители.
	dockerNameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	dockerTagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// Типы манифестов OCI и Docker. Перечислены оба набора: реестры отдают то
// один, то другой, и принимать только свой любимый значит не уметь половину
// образов.
const (
	mediaDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex           = "application/vnd.oci.image.index.v1+json"
)

// manifestAccept — что мы готовы принять. Порядок значим: реестр отдаёт
// первый поддерживаемый, и список манифестов должен идти раньше одиночного,
// иначе для multiarch-образа мы получим манифест случайной платформы.
var manifestAccept = strings.Join([]string{
	mediaOCIIndex, mediaDockerManifestList, mediaOCIManifest, mediaDockerManifest,
}, ", ")

// Docker — плагин образов контейнеров. Формат записи: image:tag.
//
// Артефактом служит образ, выгруженный в OCI-раскладке и упакованный в tar.gz:
// манифест, конфигурация и все слои. Так он и проверяется дальше по конвейеру —
// песочница получает то же самое, что запустится на машине разработчика.
//
// Multiarch обрабатывается целиком: если по тегу лежит список манифестов,
// скачиваются ВСЕ платформы. Взять одну значило бы промодерировать amd64 и
// пустить в контур непроверенный arm64 под тем же именем — а образ по тегу
// один, и подменить его после решения нельзя только потому, что проверили всё.
type Docker struct {
	// BaseURL — адрес реестра (registry-1.docker.io или внутреннее зеркало).
	BaseURL string
	// AuthURL и Service — выдача токена для анонимного доступа (у Docker Hub
	// это auth.docker.io / registry.docker.io). Пусто — реестр отвечает без
	// токена, как обычно настроены внутренние.
	AuthURL string
	Service string
	// DefaultNamespace — namespace для образов, записанных без него
	// («alpine» → «library/alpine»). Так устроен Docker Hub.
	DefaultNamespace string
	HTTP             Doer
}

func (*Docker) Code() string  { return "docker" }
func (*Docker) Title() string { return "Docker (образы)" }

func (*Docker) EntryFormat() string { return "image:tag" }

// OSVEcosystem — образ целиком ни к какой экосистеме OSV не относится: в нём
// пакеты нескольких экосистем сразу. Пустая строка честнее выдуманного имени.
func (*Docker) OSVEcosystem() string { return "" }

// NormalizeName приводит имя к виду, по которому образ уникален: строчными и с
// namespace. «alpine» и «library/alpine» — один образ, и заводить их двумя
// пакетами значило бы модерировать его дважды.
func (p *Docker) NormalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	ns := p.DefaultNamespace
	if ns == "" {
		ns = "library"
	}
	// Хост в имени (registry.example.com/team/app) не трогаем: namespace там
	// уже задан явно.
	if !strings.Contains(name, "/") {
		return ns + "/" + name
	}
	return name
}

func (*Docker) NormalizeVersion(version string) string { return strings.TrimSpace(version) }

func (*Docker) DisplayName(name string) string { return strings.TrimSpace(name) }

func (*Docker) DependencyFiles() []string {
	return []string{"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
}

func (p *Docker) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, ":")
	// Двоеточие есть и в адресе реестра с портом (registry:5000/app). Тег —
	// это то, что после последнего двоеточия и без слешей.
	if idx < 0 || strings.Contains(text[idx+1:], "/") {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату docker. Ожидается: image:tag "+
				"(например, alpine:3.19). Тег обязателен: «latest» по умолчанию "+
				"указывает на разное содержимое в разное время", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *Docker) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя образа длиннее 512 символов")
	}
	// Хост отделяем перед проверкой: в нём допустимы точки и порт.
	check := name
	if idx := strings.Index(name, "/"); idx > 0 && strings.ContainsAny(name[:idx], ".:") {
		check = name[idx+1:]
	}
	if !dockerNameRe.MatchString(strings.ToLower(check)) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя образа: «%s» (строчные буквы, цифры, «.», «-», «_», «/»)", name)
	}
	return nil
}

func (p *Docker) ValidateVersion(version string) error {
	if !dockerTagRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Тег «%s» недопустим (буквы, цифры, «.», «-», «_», до 128 символов)", version)
	}
	// latest — подвижная ссылка: сегодня и завтра это разные образы, и
	// решение, принятое по одному, относилось бы к другому.
	if strings.EqualFold(version, "latest") {
		return invalidFormat(p.EntryFormat(),
			"Тег «latest» указывает на разное содержимое в разное время, и решение по нему "+
				"завтра будет относиться к другому образу. Укажите конкретный тег")
	}
	return nil
}

// dockerManifest — и одиночный манифест, и список: поля не пересекаются,
// поэтому один тип разбирает оба, а какой пришёл — видно по mediaType.
type dockerManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		Platform  struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
}

func (m dockerManifest) isIndex() bool {
	return m.MediaType == mediaOCIIndex || m.MediaType == mediaDockerManifestList ||
		(m.MediaType == "" && len(m.Manifests) > 0)
}

// dockerConfig — конфигурация образа. Нужны дата сборки и метки: лицензию
// образы объявляют меткой org.opencontainers.image.licenses.
type dockerConfig struct {
	Created string `json:"created"`
	Config  struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

func (p *Docker) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	raw, digest, err := p.manifest(ctx, ref.Name, ref.Version)
	if err != nil {
		return Metadata{}, err
	}
	var manifest dockerManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Metadata{}, fmt.Errorf("манифест образа не разобран: %w", err)
	}

	meta := Metadata{
		Name:    ref.Name,
		Version: ref.Version,
		// ArtifactURL пустой намеренно: образ собирается из блобов, одним GET
		// его не скачать. Шаг скачивания выбирает путь по наличию Downloader.
		ArtifactFilename: fmt.Sprintf("%s-%s.oci.tar.gz",
			safeFilename(ref.Name), safeFilename(ref.RawVersion)),
		// Digest манифеста — то, что делает образ воспроизводимым: тег можно
		// переставить, digest — нет.
		Checksum:     digest,
		ChecksumAlgo: "oci-digest",
	}

	// Конфигурация лежит отдельным блобом; для списка манифестов берём её у
	// первой платформы — метки и дата сборки у платформ одного образа общие.
	configDigest := manifest.Config.Digest
	if manifest.isIndex() && len(manifest.Manifests) > 0 {
		child, _, err := p.manifest(ctx, ref.Name, manifest.Manifests[0].Digest)
		if err == nil {
			var single dockerManifest
			if json.Unmarshal(child, &single) == nil {
				configDigest = single.Config.Digest
			}
		}
	}
	if configDigest != "" {
		if body, err := p.blob(ctx, ref.Name, configDigest); err == nil {
			var cfg dockerConfig
			if json.Unmarshal(body, &cfg) == nil {
				meta.PublishedAt = parseTime(cfg.Created)
				if license := cfg.Config.Labels["org.opencontainers.image.licenses"]; license != "" {
					meta.LicenseRaw = license
					meta.LicenseSPDX = NormalizeSPDX(license)
				}
			}
		}
		// Недоступность конфигурации не валит шаг: без неё карантин будет
		// пропущен с пометкой, а лицензию определит юрист.
	}
	return meta, nil
}

// Download выгружает образ в OCI-раскладке и упаковывает в tar.gz.
//
// Раскладка именно OCI (oci-layout + index.json + blobs/sha256/…), а не
// «docker save»: она стандартизована, её принимают skopeo, podman, crane и
// сам docker, и собрать её можно из тех же блобов, что отдаёт реестр, без
// пересборки образа.
func (p *Docker) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	filename := fmt.Sprintf("%s-%s.oci.tar.gz",
		safeFilename(ref.Name), safeFilename(ref.RawVersion))

	layout := newOCILayout()
	rootRaw, rootDigest, err := p.manifest(ctx, ref.Name, ref.Version)
	if err != nil {
		return nil, "", err
	}
	var root dockerManifest
	if err := json.Unmarshal(rootRaw, &root); err != nil {
		return nil, "", fmt.Errorf("манифест образа не разобран: %w", err)
	}
	mediaType := root.MediaType
	if mediaType == "" {
		mediaType = mediaOCIManifest
		if root.isIndex() {
			mediaType = mediaOCIIndex
		}
	}
	layout.addBlob(rootDigest, rootRaw)
	layout.addRoot(mediaType, rootDigest, int64(len(rootRaw)), ref.RawVersion)

	// Список манифестов — скачиваем ВСЕ платформы: см. комментарий к типу.
	children := []string{}
	if root.isIndex() {
		for _, entry := range root.Manifests {
			children = append(children, entry.Digest)
		}
	} else {
		children = append(children, rootDigest)
	}

	var total int64
	for _, digest := range children {
		manifestRaw := rootRaw
		if digest != rootDigest {
			manifestRaw, _, err = p.manifest(ctx, ref.Name, digest)
			if err != nil {
				return nil, "", err
			}
			layout.addBlob(digest, manifestRaw)
		}
		var single dockerManifest
		if err := json.Unmarshal(manifestRaw, &single); err != nil {
			return nil, "", fmt.Errorf("манифест платформы не разобран: %w", err)
		}
		// Конфигурация и слои — то, из чего образ состоит.
		blobs := []string{single.Config.Digest}
		for _, layer := range single.Layers {
			blobs = append(blobs, layer.Digest)
		}
		for _, blobDigest := range blobs {
			if blobDigest == "" || layout.has(blobDigest) {
				// Слои у платформ пересекаются, и качать их повторно незачем.
				continue
			}
			body, err := p.blob(ctx, ref.Name, blobDigest)
			if err != nil {
				return nil, "", err
			}
			total += int64(len(body))
			// Предел проверяем ДО упаковки: образ на десятки гигабайт не
			// должен сначала оказаться в памяти целиком, а потом быть
			// отвергнут.
			if limit > 0 && total > limit {
				return nil, "", fmt.Errorf(
					"образ %s:%s больше допустимого предела (%d байт): скачано уже %d",
					ref.DisplayName, ref.RawVersion, limit, total)
			}
			layout.addBlob(blobDigest, body)
		}
	}

	payload, err := layout.tarGz(limit)
	if err != nil {
		return nil, "", err
	}
	return payload, filename, nil
}

// manifest скачивает манифест по тегу или digest. Возвращает сырые байты (их
// и надо класть в раскладку: пересериализация изменила бы digest) и сам digest.
func (p *Docker) manifest(ctx context.Context, image, reference string) ([]byte, string, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimRight(p.BaseURL, "/"), image, reference)
	body, header, err := p.get(ctx, url, manifestAccept, image)
	if err != nil {
		return nil, "", err
	}
	digest := header.Get("Docker-Content-Digest")
	if digest == "" {
		// Реестр не обязан присылать заголовок — считаем сами по тем же
		// байтам, что получили.
		sum := sha256.Sum256(body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return body, digest, nil
}

func (p *Docker) blob(ctx context.Context, image, digest string) ([]byte, error) {
	url := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimRight(p.BaseURL, "/"), image, digest)
	body, _, err := p.get(ctx, url, "*/*", image)
	if err != nil {
		return nil, err
	}
	// Digest проверяем всегда: блоб — это то, что запустится, и брать на веру
	// содержимое, пришедшее по сети, нельзя. Порча на пути обнаружится здесь,
	// а не при запуске образа.
	sum := sha256.Sum256(body)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, digest) {
		return nil, fmt.Errorf(
			"содержимое блоба %s не соответствует его digest (получено %s) — "+
				"реестр отдал не те байты", digest, got)
	}
	return body, nil
}

// get — запрос к реестру с получением токена при 401.
//
// Реестры контейнеров отвечают 401 с заголовком WWW-Authenticate даже на
// публичные образы: токен анонимный, но обязательный. Без этой ветки Docker
// Hub недоступен вовсе.
func (p *Docker) get(ctx context.Context, url, accept, image string) ([]byte, http.Header, error) {
	body, header, status, err := p.request(ctx, url, accept, "")
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusUnauthorized {
		token, tokenErr := p.token(ctx, header.Get("WWW-Authenticate"), image)
		if tokenErr != nil {
			return nil, nil, tokenErr
		}
		body, header, status, err = p.request(ctx, url, accept, token)
		if err != nil {
			return nil, nil, err
		}
	}
	switch {
	case status == http.StatusNotFound:
		return nil, nil, ErrNotFound
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, nil, fmt.Errorf(
			"реестр образов отказал в доступе (%d) к %s — образ закрытый либо "+
				"учётные данные реестра не заданы", status, image)
	case status >= 400:
		return nil, nil, fmt.Errorf("реестр образов ответил %d (%s): %s",
			status, url, excerptOf(body))
	}
	return body, header, nil
}

func (p *Docker) request(ctx context.Context, url, accept, token string) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("сборка запроса к реестру образов: %w", err)
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := doer(p.HTTP).Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("запрос к реестру образов (%s): %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("чтение ответа реестра образов: %w", err)
	}
	return body, resp.Header, resp.StatusCode, nil
}

// token получает анонимный токен по подсказке из WWW-Authenticate.
func (p *Docker) token(ctx context.Context, challenge, image string) (string, error) {
	realm, service, scope := parseChallenge(challenge)
	if realm == "" {
		realm = p.AuthURL
	}
	if service == "" {
		service = p.Service
	}
	if scope == "" {
		scope = fmt.Sprintf("repository:%s:pull", image)
	}
	if realm == "" {
		return "", fmt.Errorf(
			"реестр образов требует авторизации, но не сообщил, где брать токен " +
				"(заголовок WWW-Authenticate пуст) — задайте REGISTRY_DOCKER_AUTH_URL")
	}
	url := fmt.Sprintf("%s?service=%s&scope=%s", realm, service, scope)
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		return "", fmt.Errorf("получение токена реестра образов: %w", err)
	}
	if payload.Token != "" {
		return payload.Token, nil
	}
	if payload.AccessToken != "" {
		return payload.AccessToken, nil
	}
	return "", fmt.Errorf("реестр образов не выдал токен (%s)", url)
}

// parseChallenge разбирает `Bearer realm="…",service="…",scope="…"`.
func parseChallenge(challenge string) (realm, service, scope string) {
	challenge = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(challenge), "Bearer"))
	for _, part := range strings.Split(challenge, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "realm":
			realm = value
		case "service":
			service = value
		case "scope":
			scope = value
		}
	}
	return realm, service, scope
}

func excerptOf(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		return text[:300] + "…"
	}
	return text
}

func (p *Docker) InstallCommand(ref Ref, baseURL, repo string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(baseURL, "/"), "https://"), "http://")
	return fmt.Sprintf("docker pull %s/%s/%s:%s", host, repo, ref.Name, ref.RawVersion)
}

func (p *Docker) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/%s/%s", ref.Name, ref.RawVersion, filename)
}

var _ Downloader = (*Docker)(nil)
