// Package storage — временное хранилище артефактов и файлов отчётов
// (S3-совместимое: MinIO в прототипе, SeaweedFS в целевой инсталляции —
// см. docs/migration-to-go.md).
//
// Для артефактов это карантинная зона, а не архив: объект удаляется сразу
// после успешной выгрузки в артефактори и сразу при отклонении пакета. Для
// отчётов сканирования — наоборот, постоянное хранение: отчёт переживает и
// удаление артефакта, и повторный прогон конвейера, потому что именно им
// DevSecOps объясняет своё решение.
//
// Реализация S3 написана без внешних зависимостей: подпись AWS SigV4 — это
// сотня строк на stdlib, а альтернативы тянут в сборку либо весь aws-sdk-go-v2,
// либо клиент MinIO. Проект уже уходит с MinIO из-за AGPL (docs/migration-to-go.md),
// и заводить зависимость от его экосистемы ради четырёх операций (PUT/GET/
// DELETE/HEAD) смысла нет.
package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound — объекта нет. Отличать «нет» от «не смогли спросить» обязательно:
// шаг конвейера на первом перекачивает артефакт, на втором — зовёт человека.
var ErrNotFound = errors.New("объект не найден в хранилище")

// Object — метаданные объекта.
type Object struct {
	Bucket       string
	Key          string
	SizeBytes    int64
	ContentType  string
	LastModified time.Time
}

// Store — контракт хранилища. Реализации: S3 (бой) и Memory (тесты).
type Store interface {
	Bucket() string
	EnsureBucket(ctx context.Context) error
	Put(ctx context.Context, key string, data []byte, contentType string) (Object, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Stat(ctx context.Context, key string) (Object, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]Object, error)
}

// ArtifactKey — ключ объекта артефакта: `{manager}/{name}/{version}/{filename}`.
// Порт artifact_key из Python-версии, формат сохранён 1:1 — иначе объекты,
// положенные Python-версией, станут не видны Go-версии во время параллельной
// эксплуатации.
func ArtifactKey(manager, name, version, filename string) string {
	return fmt.Sprintf("%s/%s/%s/%s", manager, name, version, filename)
}

// ReportKey — ключ файла отчёта сканирования.
//
// Отдельный префикс `reports/`, а не рядом с артефактом: артефакты вычищаются
// целыми префиксами при отклонении пакета, а отчёты обязаны это пережить.
// itemID в пути — потому что один и тот же package_version проверяется в
// разных заявках, и отчёт каждой должен оставаться своим.
func ReportKey(itemID int64, kind, format string) string {
	return fmt.Sprintf("reports/%d/%s.%s", itemID, kind, strings.TrimPrefix(format, "."))
}

// ContentTypeFor — Content-Type по расширению файла отчёта. Браузер должен
// открыть HTML-отчёт страницей, а не предложить скачать файл.
func ContentTypeFor(format string) string {
	switch strings.TrimPrefix(strings.ToLower(format), ".") {
	case "json":
		return "application/json; charset=utf-8"
	case "html":
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
