// Package artifactstore — публикация проверенного пакета во внутренний
// артефактори. Порт backend/app/adapters/artifact_store.py.
//
// Реализаций две, и выбор между ними — не деталь: у Nexus и Artifactory
// принципиально разные протоколы выгрузки.
//
//	nexus   — Sonatype Nexus 3: компонентный REST API
//	          (POST /service/rest/v1/components?repository=…, multipart),
//	          файлы лежат под /repository/{repo}/…
//	generic — JFrog Artifactory и совместимые: PUT байтами прямо по адресу
//	          файла, с проверкой контрольной суммы на стороне сервера.
//
// Выгрузить в Nexus «как в Artifactory» нельзя: на PUT по адресу файла Nexus
// отвечает 405 Method Not Allowed — ровно это и случалось, пока go-версия
// умела только generic, а стенд работал на Nexus.
//
// ОТКРЫТЫЙ ВОПРОС по generic: CI-версия публикует пакет server-side copy'ем
// внутри Artifactory (байты не проходят через процесс), а здесь реализовано
// скачивание с upstream и PUT. Разрешает ли боевой Artifactory прямой PUT в
// moderated-репозитории — не выяснено (docs/ci-parity-gaps.md). До выяснения
// ARTIFACT_DRY_RUN=true — способ проверить доступ и креды без риска записи.
package artifactstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RemoteFile — метаданные файла в артефактори.
type RemoteFile struct {
	Path         string
	SizeBytes    int64
	Checksum     string
	LastModified time.Time
}

// Target — что публикуем. Путь внутри репозитория зависит от того, чем
// является артефактори (у Nexus своя раскладка на каждый формат), поэтому
// сюда передаётся не только готовый путь, но и сам пакет.
type Target struct {
	Repo string
	// Manager — код пакетного менеджера: по нему Nexus выбирает формат
	// компонента и имя поля с файлом.
	Manager     string
	Name        string // нормализованное имя
	DisplayName string
	Version     string // версия, как её записал разработчик
	Filename    string
	// Path — путь файла в раскладке generic-артефактори (её задаёт плагин
	// менеджера). Nexus раскладку строит сам.
	Path string
}

// Store — контракт артефактори.
type Store interface {
	// Kind — «nexus» или «generic». Нужен в сообщениях: половина ошибок
	// выгрузки — это не сломанный доступ, а не тот протокол.
	Kind() string
	// ArtifactURL — адрес, по которому пакет будет (или уже) опубликован.
	ArtifactURL(t Target) string
	// Exists — есть ли уже такой файл. Повторная публикация той же версии —
	// обычное дело (та же версия в двух заявках), и перезаписывать её нельзя.
	Exists(ctx context.Context, t Target) (bool, error)
	// Publish выгружает байты. Возвращает адрес опубликованного файла.
	Publish(ctx context.Context, t Target, data []byte) (string, error)
	// Delete снимает пакет с публикации. true — что-то действительно удалили;
	// false без ошибки означает «его там и не было», и это штатный исход:
	// отозвать могут пакет, который до артефактори не доехал.
	Delete(ctx context.Context, t Target) (bool, error)
	// StatFile — метаданные файла по пути внутри репозитория; nil, если файла
	// нет. Путь здесь сырой: это служебное чтение (снапшот OSV), а не
	// публикация пакета.
	StatFile(ctx context.Context, repo, path string) (*RemoteFile, error)
	// ReadFile — содержимое файла (нужно для снапшота OSV).
	ReadFile(ctx context.Context, repo, path string) ([]byte, error)

	// Сырые операции по произвольному пути внутри repo — промежуточная зона
	// артефактов и хранилище отчётов (см. files.go). От Publish отличаются
	// тем, что путь задаёт вызывающий, а не формат репозитория.
	WriteFile(ctx context.Context, repo, path string, data []byte, contentType string) error
	// DeleteFile: false без ошибки — файла и не было, это штатный исход.
	DeleteFile(ctx context.Context, repo, path string) (bool, error)
	ListFiles(ctx context.Context, repo, prefix string) ([]RemoteFile, error)
	// MoveFile переносит файл внутри артефактори, не прогоняя байты через
	// сервис. ErrMoveUnsupported — так делать нельзя, вызывающий обязан
	// скачать и выгрузить сам.
	MoveFile(ctx context.Context, srcRepo, srcPath, dstRepo, dstPath string) error

	// DryRun — включён ли режим «проверить доступ, но не писать».
	DryRun() bool
}

// AuthType — способ аутентификации в артефактори.
type AuthType string

const (
	AuthToken AuthType = "token" // Bearer — предпочтительно для Artifactory
	AuthBasic AuthType = "basic"
)

// Kind — тип артефактори.
const (
	KindNexus   = "nexus"
	KindGeneric = "generic"
)

// Config — параметры артефактори.
type Config struct {
	// Kind — «nexus» (по умолчанию, как в python-версии и .env.example) или
	// «generic».
	Kind     string
	BaseURL  string
	AuthType AuthType
	Token    string
	Username string
	Password string
	// DryRun — весь конвейер выполняется по-настоящему (реальное скачивание,
	// реальные сканеры), но в целевой артефактори реальные байты не пишутся.
	// Проверяется только достижимость и авторизация.
	DryRun     bool
	HTTPClient *http.Client
}

// New собирает клиент нужного типа.
func New(cfg Config) (Store, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("ARTIFACT_BASE_URL не задан")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.AuthType == "" {
		cfg.AuthType = AuthToken
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Minute}
	}
	tr := transport{cfg: cfg, client: cfg.HTTPClient}

	switch strings.ToLower(strings.TrimSpace(cfg.Kind)) {
	case "", KindNexus:
		return &Nexus{transport: tr}, nil
	case KindGeneric:
		return &Generic{transport: tr}, nil
	}
	// Опечатка в ARTIFACT_STORE не должна молча превращаться в «публикуем как
	// в Artifactory»: на Nexus это 405 на каждом пакете.
	return nil, fmt.Errorf("неизвестный тип артефактори ARTIFACT_STORE=%q (ожидается nexus или generic)", cfg.Kind)
}

// transport — общая часть обеих реализаций: авторизация и запросы.
type transport struct {
	cfg    Config
	client *http.Client
}

func (t *transport) DryRun() bool { return t.cfg.DryRun }

func (t *transport) authorize(req *http.Request) {
	switch t.cfg.AuthType {
	case AuthToken:
		if t.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+t.cfg.Token)
		}
	case AuthBasic:
		if t.cfg.Username != "" {
			req.SetBasicAuth(t.cfg.Username, t.cfg.Password)
		}
	}
}

func (t *transport) do(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("сборка запроса к артефактори: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	t.authorize(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос к артефактори (%s %s): %w", method, url, err)
	}
	return resp, nil
}

// stat — общий HEAD по готовому адресу файла.
func (t *transport) stat(ctx context.Context, url, path string) (*RemoteFile, error) {
	resp, err := t.do(ctx, http.MethodHead, url, nil, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("артефактори ответил %d на HEAD %s", resp.StatusCode, path)
	}
	file := &RemoteFile{Path: path, Checksum: resp.Header.Get("X-Checksum-Sha256")}
	if resp.ContentLength >= 0 {
		file.SizeBytes = resp.ContentLength
	}
	if modified, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		file.LastModified = modified
	}
	return file, nil
}

func (t *transport) read(ctx context.Context, url, path string) ([]byte, error) {
	resp, err := t.do(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("артефактори ответил %d на чтение %s", resp.StatusCode, path)
	}
	return io.ReadAll(resp.Body)
}

// rejected — ошибка выгрузки. 405 разбирается отдельно: это почти всегда не
// доступ и не сломанный пакет, а неверный тип артефактори или репозиторий, в
// который писать нельзя в принципе (proxy или group вместо hosted).
func rejected(kind, path string, status int, body []byte) error {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	hint := ""
	switch status {
	case http.StatusMethodNotAllowed:
		other := KindGeneric
		if kind == KindGeneric {
			other = KindNexus
		}
		hint = fmt.Sprintf(". Так отвечает артефактори, который не принимает выгрузку этим "+
			"способом: проверьте ARTIFACT_STORE (сейчас %q, второй вариант — %q) и что "+
			"репозиторий hosted, а не proxy или group", kind, other)
	case http.StatusUnauthorized, http.StatusForbidden:
		hint = ". Проверьте ARTIFACT_USER/ARTIFACT_TOKEN и права учётной записи на запись в репозиторий"
	case http.StatusNotFound:
		hint = ". Проверьте ARTIFACT_REPO_* — репозитория с таким именем в артефактори нет"
	}
	return fmt.Errorf("артефактори отклонил публикацию %s (%d)%s: %s", path, status, hint, text)
}
