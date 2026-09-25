package maintenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
	"moderation/internal/metrics"
	"moderation/internal/osv"
)

// Синхронизация снапшота базы уязвимостей.
//
// Без неё go-версия умеет только читать снапшот, который кто-то положил на
// диск руками. На стенде это выглядит так: конвейер пишет «база уязвимостей
// устарела, автоматическое одобрение отключено», и каждый пакет уходит к
// DevSecOps разбираться вручную — то есть проверка, ради которой сервис и
// затевался, не работает, хотя ошибок нигде нет.

// snapshotFromStore — переходник от артефактори к индексу уязвимостей.
// Индексу нужно ровно два вызова, и знать про типы артефактори ему незачем.
type snapshotFromStore struct{ store artifactstore.Store }

func (s snapshotFromStore) StatSnapshot(ctx context.Context, repo, path string) (*osv.RemoteSnapshot, error) {
	file, err := s.store.StatFile(ctx, repo, path)
	if err != nil || file == nil {
		return nil, err
	}
	return &osv.RemoteSnapshot{
		Checksum: file.Checksum, LastModified: file.LastModified, SizeBytes: file.SizeBytes,
	}, nil
}

func (s snapshotFromStore) ReadSnapshot(ctx context.Context, repo, path string) ([]byte, error) {
	return s.store.ReadFile(ctx, repo, path)
}

// OSVConfig — что нужно синхронизации.
type OSVConfig struct {
	// Kind — способ доставки снапшота: artifactory, http или file.
	// Пустой означает artifactory — так это работало до появления выбора.
	Kind osv.SourceKind
	// Repo и Path — репозиторий артефактори и путь в нём (Kind=artifactory).
	Repo string
	Path string
	// Snapshots — несколько архивов одного составного индекса. Для
	// artifactory это отдельные выгрузки PyPI и npm. Если список пуст,
	// сохраняется совместимость с одиночным Path/URL/File.
	Snapshots []osv.SnapshotSpec
	// URL, Token — адрес файла и токен зеркала (Kind=http).
	URL   string
	Token string
	// File — путь к zip-файлу снапшота на диске (Kind=file).
	File string
	// LocalPath — куда раскладывается снапшот.
	LocalPath string
}

// source собирает источник снапшота по настройке.
//
// Разные источники отвечают на один и тот же вопрос — «откуда приехал файл», —
// и дальше по коду не различаются: снапшот всё равно раскладывается на диск
// целиком, версия фиксируется в базе, а проверка идёт по локальным данным.
func (cfg OSVConfig) source(store artifactstore.Store) (osv.SnapshotSource, error) {
	switch cfg.Kind {
	case osv.SourceHTTP:
		header := map[string]string{}
		if cfg.Token != "" {
			header["Authorization"] = "Bearer " + cfg.Token
		}
		return osv.HTTPSource{URL: cfg.URL, Header: header}, nil
	case osv.SourceFile:
		return osv.FileSource{Path: cfg.File}, nil
	case "", osv.SourceArtifactory:
		if store == nil {
			return nil, errors.New("артефактори не настроено — снапшот OSV брать неоткуда")
		}
		return snapshotFromStore{store: store}, nil
	}
	return nil, fmt.Errorf("неизвестный источник снапшота OSV: %q", cfg.Kind)
}

// location — где снапшот искали, для сообщений.
func (cfg OSVConfig) location() string {
	switch cfg.Kind {
	case osv.SourceHTTP:
		return cfg.URL
	case osv.SourceFile:
		return cfg.File
	}
	if len(cfg.Snapshots) > 0 {
		paths := make([]string, 0, len(cfg.Snapshots))
		for _, snapshot := range cfg.Snapshots {
			paths = append(paths, cfg.Repo+"/"+snapshot.Path)
		}
		return strings.Join(paths, ", ")
	}
	return cfg.Repo + "/" + cfg.Path
}

// SyncResult — итог одной синхронизации.
type SyncResult struct {
	// Updated — снапшот действительно обновился. false означает «в артефактори
	// лежит тот же самый», а не «не получилось».
	Updated bool
	Version string
	Records int
	// IndexVersionID — строка vuln_index_version, по которой дальше идёт
	// перепроверка одобренных пакетов.
	IndexVersionID *int64
}

// SyncOSVSnapshot загружает снапшот, если в артефактори появился новый.
//
// Версия снапшота фиксируется в базе: по ней видно, чем именно проверяли
// пакет, и её же показывает экран «Настройка». Прежние версии помечаются
// неактивными — активной может быть только одна.
func (s *Service) SyncOSVSnapshot(ctx context.Context, cfg OSVConfig, force bool) (SyncResult, error) {
	src, err := cfg.source(s.Artifacts)
	if err != nil {
		return SyncResult{}, err
	}
	s.logger().Info("синхронизация снапшота OSV начата",
		"источник", string(cfg.Kind), "откуда", cfg.location(), "force", force)
	src = loggingSnapshotSource{next: src, logger: s.logger()}
	index := osv.NewSnapshotIndex(cfg.LocalPath)

	var info *osv.IndexVersion
	if len(cfg.Snapshots) > 0 {
		info, err = index.SyncMany(ctx, src, cfg.Repo, cfg.Snapshots, force)
	} else {
		info, err = index.Sync(ctx, src, cfg.Repo, cfg.Path, force)
	}
	if err != nil {
		return SyncResult{}, err
	}
	if info == nil {
		current, err := index.CurrentVersion(ctx)
		if err != nil || current == nil {
			return SyncResult{}, err
		}
		age := ageDays(*current, s.now())
		// Возраст снапшота — главная метрика для алерта: устаревшая база не
		// роняет сервис, она тихо переводит каждый пакет на ручное решение
		// DevSecOps, и снаружи это выглядит как «модерация стала медленной».
		metrics.OSVIndexAgeDays.Set(age)
		s.logger().Info("снапшот OSV актуален", "версия", current.Version, "возраст, дней", age)
		return SyncResult{Version: current.Version, Records: current.RecordCount}, nil
	}

	row, err := s.Repo.UpsertVulnIndexVersion(ctx, domain.VulnIndexVersion{
		Version: info.Version, Source: info.Source, Checksum: strPtr(info.Checksum),
		RemotePath: strPtr(info.RemotePath), LocalPath: strPtr(info.LocalPath),
		PublishedAt: info.PublishedAt, RecordCount: &info.RecordCount,
	})
	if err != nil {
		return SyncResult{}, err
	}
	if err := s.Repo.DeactivateOtherIndexVersions(ctx, row.ID); err != nil {
		// Не повод считать загрузку неудачной: снапшот уже разложен и работает.
		s.logger().Warn("прежние версии снапшота не помечены неактивными", "error", err)
	}
	s.audit(ctx, "osv_snapshot_synced", "vuln_index_version", fmt.Sprint(row.ID),
		map[string]any{"version": info.Version, "records": info.RecordCount})
	// Только что загруженный снапшот — нулевого возраста, если издатель
	// проставил дату. Ставим по той же формуле, а не нулём: дата публикации
	// может быть и вчерашней, и тогда «0» был бы неправдой.
	metrics.OSVIndexAgeDays.Set(ageDays(osv.IndexVersion{PublishedAt: info.PublishedAt}, s.now()))
	s.logger().Info("снапшот OSV загружен", "версия", info.Version,
		"записей", info.RecordCount, "источник", string(cfg.Kind), "откуда", cfg.location())

	return SyncResult{
		Updated: true, Version: info.Version, Records: info.RecordCount,
		IndexVersionID: &row.ID,
	}, nil
}

// loggingSnapshotSource делает продолжительную загрузку видимой в логах.
// Без этих сообщений CLI молчал до полной загрузки и распаковки обоих ZIP,
// поэтому нормальная работа выглядела как зависание.
type loggingSnapshotSource struct {
	next   osv.SnapshotSource
	logger *slog.Logger
}

func (s loggingSnapshotSource) StatSnapshot(
	ctx context.Context, repo, path string,
) (*osv.RemoteSnapshot, error) {
	s.logger.Info("проверка архива OSV", "архив", path)
	remote, err := s.next.StatSnapshot(ctx, repo, path)
	if err == nil && remote != nil {
		s.logger.Info("архив OSV найден", "архив", path, "размер, байт", remote.SizeBytes)
	}
	return remote, err
}

func (s loggingSnapshotSource) ReadSnapshot(
	ctx context.Context, repo, path string,
) ([]byte, error) {
	started := time.Now()
	s.logger.Info("скачивание архива OSV", "архив", path)
	payload, err := s.next.ReadSnapshot(ctx, repo, path)
	if err == nil {
		s.logger.Info("архив OSV скачан, начинается распаковка", "архив", path,
			"размер, байт", len(payload), "время", time.Since(started).Round(time.Millisecond))
	}
	return payload, err
}

func ageDays(v osv.IndexVersion, now time.Time) float64 {
	if age := v.AgeDays(now); age != nil {
		return *age
	}
	return -1
}

func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
