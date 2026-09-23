package pipeline

import (
	"context"
	"crypto/md5"  //nolint:gosec // не для безопасности: реестр заявляет md5, сверяем с ним
	"crypto/sha1" //nolint:gosec // то же самое: npm shasum — sha1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"moderation/internal/storage"
)

// --------------------------------------------------------------------------- шаг 4
// DownloadStep — скачивание артефакта из реестра пакетного менеджера напрямую
// (не через proxy-репозиторий артефактори), через корпоративный HTTP_PROXY, в
// промежуточную зону.
//
// Промежуточная зона — отдельный raw-репозиторий артефактори
// (ARTIFACT_REPO_STAGING), а не объектное хранилище рядом: пакет и так поедет в
// артефактори, и держать его до этого в другой системе значит админить две.
// Публикация после этого становится переносом файла внутри одной системы
// (PublishStep), а не повторной выгрузкой байтов.
//
// Из зоны пакет уходит всегда: при публикации — переносом, при отклонении и по
// таймауту — удалением (purgeArtifact, maintenance.CleanupOrphanObjects). Из
// репозитория, откуда ставят разработчики, он при этом не виден: конфигурация
// на старте проверяет, что промежуточная зона не совпадает ни с одним целевым
// репозиторием.
type DownloadStep struct{}

func (DownloadStep) Code() string { return "download" }

func (DownloadStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	meta, err := pc.Metadata(ctx)
	if err != nil {
		return Fail(fmt.Sprintf("Метаданные версии не получены из реестра: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Проверьте, что версия опубликована в реестре, и повторите заявку."), nil
	}
	if meta.ArtifactURL == "" {
		return Fail("Реестр не сообщил URL артефакта — скачать пакет невозможно.").
			WithStatus("failed", "failed").
			WithNextAction("Проверьте, что версия опубликована в реестре, и повторите заявку."), nil
	}

	filename := meta.ArtifactFilename
	if filename == "" {
		filename = fmt.Sprintf("%s-%s", pc.Package.Name, pc.Version.RawVersion)
	}

	limit := pc.Config.MaxArtifactSizeBytes
	if limit <= 0 {
		limit = 512 * 1024 * 1024
	}
	payload, err := pc.Deps.Fetch.Fetch(ctx, meta.ArtifactURL, limit)
	if err != nil {
		return Fail(fmt.Sprintf("Артефакт не скачан: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Повторите заявку позже: реестр не отдал артефакт."), nil
	}

	digest := sha256.Sum256(payload)
	sha := hex.EncodeToString(digest[:])

	// Контрольная сумма из реестра сверяется до записи в хранилище: артефакт,
	// перезалитый в реестре между запросом метаданных и скачиванием, не должен
	// уехать дальше по конвейеру.
	checksumNote := "реестр не сообщил контрольную сумму"
	if meta.Checksum != "" && meta.ChecksumAlgo != "" {
		actual, ok := hashWith(meta.ChecksumAlgo, payload)
		switch {
		case !ok:
			// Неизвестный алгоритм (например, go h1) — сверить нечем, и
			// притворяться, что сверили, нельзя.
			checksumNote = fmt.Sprintf("контрольная сумма %s не сверялась: алгоритм не поддержан",
				meta.ChecksumAlgo)
		case !strings.EqualFold(actual, strings.TrimSpace(meta.Checksum)):
			return Fail(fmt.Sprintf(
				"Контрольная сумма артефакта не совпала с заявленной в реестре (%s): "+
					"ожидалось %s…, получено %s….",
				meta.ChecksumAlgo, truncate(meta.Checksum, 16), truncate(actual, 16))).
				WithDetails(map[string]any{
					"expected": meta.Checksum, "actual": actual, "algo": meta.ChecksumAlgo,
				}).
				WithStatus("failed", "failed").
				WithNextAction("Повторите заявку позже: артефакт в реестре мог быть перезалит."), nil
		default:
			checksumNote = fmt.Sprintf("контрольная сумма %s совпала", meta.ChecksumAlgo)
		}
	}

	key := storage.ArtifactKey(pc.Package.Manager, pc.Package.Name, pc.Version.RawVersion, filename)
	if _, err := pc.Deps.Storage.Put(ctx, key, payload, "application/octet-stream"); err != nil {
		return StepOutcome{}, fmt.Errorf("запись артефакта в промежуточную зону: %w", err)
	}

	artifact, err := pc.Deps.Repo.GetOrCreateArtifact(ctx, pc.Version.ID, filename)
	if err != nil {
		return StepOutcome{}, err
	}
	artifact.SourceURL = ptr(meta.ArtifactURL)
	artifact.SizeBytes = ptr(int64(len(payload)))
	artifact.SHA256 = ptr(sha)
	artifact.ChecksumAlgo = nilIfEmpty(meta.ChecksumAlgo)
	artifact.DeclaredChecksum = nilIfEmpty(meta.Checksum)
	artifact.StagingRepo = ptr(pc.Deps.Storage.Bucket())
	artifact.StagingPath = ptr(key)
	artifact.StagedAt = timePtr(pc.now())
	artifact.StagingClearedAt = nil
	if err := pc.Deps.Repo.UpdateArtifactDownloaded(ctx, artifact); err != nil {
		return StepOutcome{}, err
	}
	pc.SetPayload(payload)

	return Pass(fmt.Sprintf(
		"Артефакт %s (%d КБ) скачан из реестра, %s; помещён в промежуточную зону %s: %s",
		filename, len(payload)/1024, checksumNote, pc.Deps.Storage.Bucket(), key)).
		WithDetails(map[string]any{
			"staging_repo": pc.Deps.Storage.Bucket(), "staging_path": key,
			"sha256": sha, "size_bytes": len(payload), "filename": filename,
		}), nil
}

// hashWith считает сумму заявленным реестром алгоритмом. ok=false — алгоритм
// не поддержан: сверить нечем, и притворяться, что сверили, нельзя.
func hashWith(algo string, payload []byte) (string, bool) {
	var h hash.Hash
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "sha1":
		h = sha1.New() //nolint:gosec // сверка с заявленным реестром значением, не защита
	case "md5":
		h = md5.New() //nolint:gosec // то же самое
	default:
		return "", false
	}
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil)), true
}

func truncate(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

func nilIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
