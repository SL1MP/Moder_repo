package osv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"moderation/internal/unpack"
)

// Загрузка снапшота OSV из артефактори.
//
// Сеть к osv.dev по-прежнему не используется: решение о пакете принимается по
// данным, которые заказчик сам положил во внутренний репозиторий и может
// предъявить. Эта часть отвечает на вопрос «как они там оказываются».

// RemoteSnapshot — метаданные файла снапшота в артефактори.
type RemoteSnapshot struct {
	Checksum     string
	LastModified time.Time
	SizeBytes    int64
}

// SnapshotSource — откуда берётся снапшот. Интерфейс объявлен здесь, а не
// импортируется из artifactstore: индексу уязвимостей нужно ровно два вызова,
// и знать про типы артефактори ему незачем.
type SnapshotSource interface {
	StatSnapshot(ctx context.Context, repo, path string) (*RemoteSnapshot, error)
	ReadSnapshot(ctx context.Context, repo, path string) ([]byte, error)
}

// ErrSnapshotMissing — в артефактори нет файла снапшота. Отдельная ошибка:
// «снапшот не выложили» — это не сбой сервиса и не пустая база, а состояние,
// о котором администратору надо сказать прямо.
var ErrSnapshotMissing = fmt.Errorf("снапшот базы OSV не найден в артефактори")

// snapshotLimits — границы распаковки снапшота. Отдельные от пакетных:
// снапшот — это десятки тысяч мелких json-файлов, и лимит в 20 000 файлов
// (норма для пакета) обрезал бы базу молча.
func snapshotLimits() unpack.Limits {
	return unpack.Limits{
		MaxTotalBytes: 4 << 30,
		MaxFileBytes:  32 << 20,
		MaxFiles:      1_000_000,
		MaxDepth:      1,
	}
}

// Sync скачивает снапшот, если в артефактори лежит не тот, что уже разложен.
//
// Возвращает nil, nil, когда загрузка не потребовалась: вызывающий код
// отличает «обновили» от «и так актуально» без разбора текста.
//
// Идемпотентна: повторный вызов с тем же снапшотом ничего не меняет.
func (s *SnapshotIndex) Sync(ctx context.Context, src SnapshotSource, repo, path string, force bool) (*IndexVersion, error) {
	remote, err := src.StatSnapshot(ctx, repo, path)
	if err != nil {
		return nil, err
	}
	if remote == nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrSnapshotMissing, repo, path)
	}
	remoteVersion := snapshotVersion(*remote)

	current, err := s.CurrentVersion(ctx)
	if err != nil {
		return nil, err
	}
	if !force && current != nil && current.Version == remoteVersion {
		return nil, nil
	}

	payload, err := src.ReadSnapshot(ctx, repo, path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	checksum := hex.EncodeToString(digest[:])
	// Сверяем, только если артефактори отдал именно sha256: в заголовке может
	// оказаться ETag или sha1, и сравнивать их с sha256 бессмысленно.
	if len(remote.Checksum) == 64 && !strings.EqualFold(remote.Checksum, checksum) {
		return nil, fmt.Errorf(
			"контрольная сумма снапшота OSV не совпала: артефактори заявил %s, скачано %s",
			remote.Checksum, checksum)
	}

	staging := s.Root + ".new"
	if err := os.RemoveAll(staging); err != nil {
		return nil, fmt.Errorf("очистка каталога загрузки: %w", err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return nil, fmt.Errorf("создание каталога загрузки: %w", err)
	}
	count, err := extractSnapshot(payload, staging)
	if err != nil {
		_ = os.RemoveAll(staging)
		return nil, err
	}

	published := remote.LastModified
	if published.IsZero() {
		published = time.Now().UTC()
	}
	info := &IndexVersion{
		Version: remoteVersion, Source: s.Source(), Checksum: checksum,
		PublishedAt: &published, RemotePath: path, RecordCount: count, LocalPath: s.Root,
	}
	meta, err := json.Marshal(snapshotMeta{
		Version: info.Version, Checksum: info.Checksum,
		PublishedAt: published.UTC().Format(time.RFC3339),
		RemotePath:  info.RemotePath, RecordCount: info.RecordCount,
	})
	if err != nil {
		_ = os.RemoveAll(staging)
		return nil, fmt.Errorf("метаданные снапшота не собраны: %w", err)
	}
	if err := os.WriteFile(filepath.Join(staging, "snapshot.json"), meta, 0o644); err != nil {
		_ = os.RemoveAll(staging)
		return nil, fmt.Errorf("запись метаданных снапшота: %w", err)
	}

	if err := swapDir(s.Root, staging); err != nil {
		return nil, err
	}
	// Кэш собран по прежнему снапшоту: без сброса шаг проверки продолжил бы
	// отвечать по старым данным, хотя на диске уже новые.
	s.mu.Lock()
	s.cache = map[string][]Record{}
	s.mu.Unlock()
	return info, nil
}

// snapshotVersion — как называется версия снапшота. Хеш предпочтительнее даты:
// одинаковый файл, перевыложенный дважды, не должен считаться новой версией и
// запускать перепроверку всех одобренных пакетов.
func snapshotVersion(remote RemoteSnapshot) string {
	if len(remote.Checksum) >= 16 {
		return remote.Checksum[:16]
	}
	stamp := remote.LastModified
	if stamp.IsZero() {
		stamp = time.Now().UTC()
	}
	return stamp.UTC().Format("20060102T150405Z")
}

// extractSnapshot раскладывает архив в целевой каталог по схеме
// `{экосистема}/{идентификатор}.json`.
func extractSnapshot(payload []byte, target string) (int, error) {
	result, err := unpack.Artifact(payload, "snapshot.zip", snapshotLimits())
	if err != nil {
		return 0, fmt.Errorf("распаковка снапшота OSV: %w", err)
	}
	defer unpack.Cleanup(result)
	if result.Truncated {
		// Обрезанная база уязвимостей хуже отсутствующей: по ней конвейер
		// выносит вердикт «чисто» на пакетах, записи о которых не доехали.
		return 0, fmt.Errorf("снапшот OSV не поместился в лимиты распаковки — база была бы неполной")
	}

	count := 0
	err = filepath.Walk(result.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			return nil
		}
		rel, err := filepath.Rel(result.Root, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(target, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := copyFile(path, dest); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("раскладка снапшота OSV: %w", err)
	}
	if count == 0 {
		return 0, fmt.Errorf("снапшот OSV не содержит ни одной записи .json")
	}
	return count, nil
}

func copyFile(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(to)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
}

// swapDir подменяет каталог снапшота новым.
//
// Сначала переименование старого, потом нового на его место: если делать
// «удалить и переименовать», между двумя операциями снапшота нет вовсе — и
// параллельный прогон конвейера в этот момент решит, что база не загружена, и
// отправит пакет к DevSecOps.
func swapDir(root, staging string) error {
	previous := root + ".old"
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("очистка прежнего снапшота: %w", err)
	}
	if _, err := os.Stat(root); err == nil {
		if err := os.Rename(root, previous); err != nil {
			return fmt.Errorf("перенос прежнего снапшота: %w", err)
		}
	}
	if err := os.Rename(staging, root); err != nil {
		// Пытаемся вернуть прежний: остаться совсем без снапшота хуже, чем со
		// старым.
		_ = os.Rename(previous, root)
		return fmt.Errorf("установка нового снапшота: %w", err)
	}
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("удаление прежнего снапшота: %w", err)
	}
	return nil
}
