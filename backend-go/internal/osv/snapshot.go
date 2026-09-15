package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SnapshotIndex — локальный снапшот OSV, полученный из артефактори. Сеть к
// osv.dev не используется: решение о пакете принимается по данным, которые
// заказчик сам положил во внутренний репозиторий и может предъявить.
//
// Раскладка каталога — как у Python-версии: snapshot.json в корне с версией и
// датой, записи — JSON-файлы, сгруппированные по экосистемам.
type SnapshotIndex struct {
	Root string

	mu    sync.RWMutex
	cache map[string][]Record // ключ: экосистема|имя
}

func NewSnapshotIndex(root string) *SnapshotIndex {
	return &SnapshotIndex{Root: root, cache: map[string][]Record{}}
}

func (*SnapshotIndex) Source() string { return "snapshot" }

type snapshotMeta struct {
	Version     string `json:"version"`
	Checksum    string `json:"checksum"`
	PublishedAt string `json:"published_at"`
	RemotePath  string `json:"remote_path"`
	RecordCount int    `json:"record_count"`
}

// CurrentVersion — nil означает «снапшот ни разу не загружался». Это не
// «уязвимостей нет»: шаг обязан превратить nil в решение DevSecOps.
func (s *SnapshotIndex) CurrentVersion(context.Context) (*IndexVersion, error) {
	data, err := os.ReadFile(filepath.Join(s.Root, "snapshot.json"))
	if err != nil {
		return nil, nil //nolint:nilerr // отсутствие снапшота — не ошибка чтения, а состояние
	}
	var meta snapshotMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("метаданные снапшота OSV не разобраны: %w", err)
	}
	version := meta.Version
	if version == "" {
		version = "unknown"
	}
	info := &IndexVersion{
		Version: version, Source: s.Source(), Checksum: meta.Checksum,
		RemotePath: meta.RemotePath, RecordCount: meta.RecordCount, LocalPath: s.Root,
	}
	if published, err := time.Parse(time.RFC3339, meta.PublishedAt); err == nil {
		utc := published.UTC()
		info.PublishedAt = &utc
	}
	return info, nil
}

func (s *SnapshotIndex) LocalDBPath() string {
	if info, err := os.Stat(s.Root); err == nil && info.IsDir() {
		return s.Root
	}
	return ""
}

// Query — уязвимости конкретной версии пакета по снапшоту.
func (s *SnapshotIndex) Query(_ context.Context, manager, name, version string) ([]Finding, error) {
	ecosystem, ok := Ecosystems[manager]
	if !ok {
		return nil, fmt.Errorf("менеджер %q не отображён на экосистему OSV", manager)
	}
	if info, err := os.Stat(s.Root); err != nil || !info.IsDir() {
		return nil, fmt.Errorf(
			"локальная база OSV не загружена (%s). Запустите синхронизацию снапшота", s.Root)
	}

	records, err := s.recordsFor(ecosystem, name)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, record := range records {
		if finding, hit := FindingFromRecord(record, manager, version); hit {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// recordsFor — записи снапшота, упоминающие пакет. Результат кешируется: за
// один прогон конвейера обходить каталог базы несколько раз незачем, а база
// эта — десятки тысяч файлов.
func (s *SnapshotIndex) recordsFor(ecosystem, name string) ([]Record, error) {
	key := strings.ToLower(ecosystem + "|" + name)

	s.mu.RLock()
	cached, ok := s.cache[key]
	s.mu.RUnlock()
	if ok {
		return cached, nil
	}

	target := strings.ToLower(name)
	// Порядок как в Python-версии: сначала каталог экосистемы, потом корень.
	candidates := []string{
		filepath.Join(s.Root, ecosystem),
		filepath.Join(s.Root, strings.ToLower(ecosystem)),
		s.Root,
	}

	var out []Record
	seen := map[string]struct{}{}
	for _, base := range candidates {
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil //nolint:nilerr // недоступный элемент пропускается
			}
			if !strings.HasSuffix(strings.ToLower(info.Name()), ".json") || info.Name() == "snapshot.json" {
				return nil
			}
			if _, dup := seen[info.Name()]; dup {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil //nolint:nilerr // битый файл базы не должен ронять шаг
			}
			var record Record
			if err := json.Unmarshal(data, &record); err != nil {
				return nil //nolint:nilerr // см. выше
			}
			if !recordMentions(record, ecosystem, target) {
				return nil
			}
			seen[info.Name()] = struct{}{}
			out = append(out, record)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("обход снапшота OSV (%s): %w", base, err)
		}
		if len(out) > 0 {
			break
		}
	}

	s.mu.Lock()
	s.cache[key] = out
	s.mu.Unlock()
	return out, nil
}

func recordMentions(record Record, ecosystem, name string) bool {
	for _, affected := range record.Affected {
		entryEcosystem, _, _ := strings.Cut(affected.Package.Ecosystem, ":")
		if !strings.EqualFold(entryEcosystem, ecosystem) {
			continue
		}
		if strings.EqualFold(affected.Package.Name, name) {
			return true
		}
	}
	return false
}

// StaticIndex — индекс из заранее подготовленного набора записей. Для тестов
// конвейера и для режима, в котором снапшот не нужен.
type StaticIndex struct {
	Version *IndexVersion
	Records []Record
}

func (*StaticIndex) Source() string { return "static" }

func (s *StaticIndex) CurrentVersion(context.Context) (*IndexVersion, error) {
	return s.Version, nil
}

func (*StaticIndex) LocalDBPath() string { return "" }

func (s *StaticIndex) Query(_ context.Context, manager, name, version string) ([]Finding, error) {
	ecosystem := Ecosystems[manager]
	var findings []Finding
	for _, record := range s.Records {
		if !recordMentions(record, ecosystem, strings.ToLower(name)) {
			continue
		}
		if finding, hit := FindingFromRecord(record, manager, version); hit {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}
