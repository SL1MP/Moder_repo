package maintenance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
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
	Repo string
	Path string
	// LocalPath — куда раскладывается снапшот.
	LocalPath string
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
	if s.Artifacts == nil {
		return SyncResult{}, errors.New("артефактори не настроено — снапшот OSV брать неоткуда")
	}
	index := osv.NewSnapshotIndex(cfg.LocalPath)

	info, err := index.Sync(ctx, snapshotFromStore{store: s.Artifacts}, cfg.Repo, cfg.Path, force)
	if err != nil {
		return SyncResult{}, err
	}
	if info == nil {
		current, err := index.CurrentVersion(ctx)
		if err != nil || current == nil {
			return SyncResult{}, err
		}
		s.logger().Info("снапшот OSV актуален", "версия", current.Version,
			"возраст, дней", ageDays(*current, s.now()))
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
	s.logger().Info("снапшот OSV загружен",
		"версия", info.Version, "записей", info.RecordCount)

	return SyncResult{
		Updated: true, Version: info.Version, Records: info.RecordCount,
		IndexVersionID: &row.ID,
	}, nil
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
