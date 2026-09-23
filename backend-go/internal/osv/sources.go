package osv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Откуда берётся снапшот базы уязвимостей.
//
// Источник один на инсталляцию и выбирается настройкой OSV_DB_SOURCE. Разбор
// вариантов — docs/osv-snapshot.md; здесь по одному абзацу на каждый, чтобы
// читающий код видел, чем они отличаются, не уходя в документацию.
//
// Общее у всех трёх: снапшот кладётся на диск воркера ЦЕЛИКОМ, и решение по
// каждому пакету принимается по локальным данным. Сеть во время проверки не
// используется, а версия снапшота фиксируется в базе — по ней потом видно,
// чем именно проверяли пакет, и её же показывает экран «Настройка». Источник
// отвечает только на вопрос «откуда файл приехал», и заменить один на другой
// можно, не трогая ни конвейер, ни отчёты.

// SourceKind — способ доставки снапшота.
type SourceKind string

const (
	// SourceArtifactory — файл лежит в raw-репозитории артефактори, сервис его
	// читает. Так это работает сейчас и так задумано по умолчанию: артефактори
	// в контуре уже есть, доступ к нему у сервиса уже настроен, версия файла
	// берётся из его же метаданных, а выкладывает снапшот существующий
	// ежедневный скрипт заказчика — сервис туда ничего не пишет.
	SourceArtifactory SourceKind = "artifactory"

	// SourceHTTP — файл отдаётся по произвольному адресу: внутреннее зеркало,
	// nginx с примонтированным каталогом, объектное хранилище со ссылкой.
	// Нужен там, где выкладывать снапшот в артефактори неудобно или нечем, а
	// поднять раздачу файла по http — вопрос десяти строк конфигурации.
	//
	// Версия определяется так же, как у артефактори: по ETag/Last-Modified,
	// то есть по метаданным HTTP. Если сервер их не отдаёт, версией станет
	// хеш скачанного файла — тогда каждая синхронизация будет качать снапшот
	// целиком, чтобы понять, изменился ли он.
	SourceHTTP SourceKind = "http"

	// SourceFile — файл уже лежит на диске воркера: его кладёт туда чужой
	// процесс (cron на хосте, sidecar, смонтированный том, CSI-раздел).
	// Сервис его только читает.
	//
	// Самый простой вариант с точки зрения сервиса и самый неудобный с точки
	// зрения эксплуатации: за доставку файла на каждый воркер отвечает
	// кто-то снаружи, и если он перестанет это делать, сервис узнает об этом
	// только по возрасту снапшота.
	SourceFile SourceKind = "file"
)

// ParseSourceKind разбирает значение настройки.
func ParseSourceKind(value string) (SourceKind, error) {
	switch SourceKind(strings.ToLower(strings.TrimSpace(value))) {
	case "", SourceArtifactory:
		return SourceArtifactory, nil
	case SourceHTTP:
		return SourceHTTP, nil
	case SourceFile:
		return SourceFile, nil
	}
	// Опечатка не должна молча превращаться в «читаем из артефактори»: там
	// файла может не быть вовсе, и сервис будет месяцами работать с пустой
	// базой, отправляя каждый пакет к DevSecOps.
	return "", fmt.Errorf(
		"неизвестный источник снапшота OSV_DB_SOURCE=%q (ожидается artifactory, http или file)",
		value)
}

// --------------------------------------------------------------------------- http

// HTTPSource — снапшот по адресу.
//
// repo и path в вызовах игнорируются: адрес задан целиком настройкой. Оставлены
// в сигнатуре, потому что интерфейс общий на все источники, а заводить ради
// одного из них второй интерфейс значило бы дублировать и Sync.
type HTTPSource struct {
	// URL — адрес файла снапшота.
	URL string
	// Header — дополнительные заголовки, например токен внутреннего зеркала.
	Header map[string]string
	Client *http.Client
}

func (s HTTPSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	// Снапшот OSV — сотни мегабайт: минутного таймаута тут мало.
	return &http.Client{Timeout: 30 * time.Minute}
}

func (s HTTPSource) do(ctx context.Context, method string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("сборка запроса за снапшотом OSV: %w", err)
	}
	for name, value := range s.Header {
		req.Header.Set(name, value)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос за снапшотом OSV (%s %s): %w", method, s.URL, err)
	}
	return resp, nil
}

func (s HTTPSource) StatSnapshot(ctx context.Context, _, _ string) (*RemoteSnapshot, error) {
	resp, err := s.do(ctx, http.MethodHead)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	// HEAD поддерживают не все раздачи. Отказ в нём — не повод считать, что
	// снапшота нет: пустой ответ заставит Sync скачать файл и определить
	// версию по его хешу.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return &RemoteSnapshot{}, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("снапшот OSV: сервер ответил %d на HEAD %s", resp.StatusCode, s.URL)
	}

	snapshot := &RemoteSnapshot{SizeBytes: resp.ContentLength}
	// ETag — ближайший аналог контрольной суммы, который отдаёт HTTP. Кавычки
	// и префикс слабого валидатора снимаем: они часть синтаксиса заголовка, а
	// не значения, и с ними одна и та же версия выглядела бы разной.
	if etag := resp.Header.Get("ETag"); etag != "" {
		snapshot.Checksum = strings.Trim(strings.TrimPrefix(etag, "W/"), `"`)
	}
	if modified, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		snapshot.LastModified = modified
	}
	return snapshot, nil
}

func (s HTTPSource) ReadSnapshot(ctx context.Context, _, _ string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("снапшот OSV: сервер ответил %d на %s", resp.StatusCode, s.URL)
	}
	return io.ReadAll(resp.Body)
}

// --------------------------------------------------------------------------- file

// FileSource — снапшот уже лежит на диске.
type FileSource struct {
	// Path — файл снапшота (zip), а не каталог с распакованным: распаковкой
	// занимается сам индекс, и делать это по-разному в зависимости от
	// источника значило бы получить два разных формата «готового снапшота».
	Path string
}

func (s FileSource) StatSnapshot(_ context.Context, _, _ string) (*RemoteSnapshot, error) {
	info, err := os.Stat(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение снапшота OSV %s: %w", s.Path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf(
			"OSV_DB_FILE указывает на каталог (%s), а нужен zip-файл снапшота", s.Path)
	}
	// Контрольной суммы у файла на диске нет, и считать её на каждом HEAD
	// незачем: снапшот — сотни мегабайт, а проверка идёт раз в несколько
	// часов. Версией служит время изменения и размер — этого достаточно,
	// чтобы заметить, что файл подменили.
	return &RemoteSnapshot{
		LastModified: info.ModTime().UTC(),
		SizeBytes:    info.Size(),
	}, nil
}

func (s FileSource) ReadSnapshot(_ context.Context, _, _ string) ([]byte, error) {
	body, err := os.ReadFile(filepath.Clean(s.Path))
	if err != nil {
		return nil, fmt.Errorf("чтение снапшота OSV %s: %w", s.Path, err)
	}
	return body, nil
}

// --------------------------------------------------------------------------- общее

// ChecksumOf — sha256 содержимого. Нужен источникам, которые не сообщают
// версию своими метаданными: тогда версией становится хеш самого файла.
func ChecksumOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
