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

	"moderation/internal/registry"
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
	if pc.Package.Manager == "git" {
		return downloadGitMirror(ctx, pc)
	}
	meta, err := pc.Metadata(ctx)
	if err != nil {
		return Fail(fmt.Sprintf("Метаданные версии не получены из реестра: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Проверьте, что версия опубликована в реестре, и повторите заявку."), nil
	}
	// LicenseStep and SBOMStep start concurrently after download. Persist the
	// metadata-derived license before that fan-out so both see one immutable
	// value instead of racing to mutate Context.Version.
	if pc.Version.LicenseSPDX == nil && pc.Version.LicenseRaw == nil &&
		(meta.LicenseSPDX != "" || meta.LicenseRaw != "") {
		spdx, raw, source := meta.LicenseSPDX, meta.LicenseRaw, "registry"
		if err := pc.Deps.Repo.SetDetectedLicense(
			ctx, pc.Version.ID, spdx, raw, source); err != nil {
			return StepOutcome{}, err
		}
		if spdx != "" {
			pc.Version.LicenseSPDX = &spdx
		}
		if raw != "" {
			pc.Version.LicenseRaw = &raw
		}
		pc.Version.LicenseSource = &source
	}

	limit := pc.Config.MaxArtifactSizeBytes
	if pc.Package.Manager == "docker" && pc.Config.MaxDockerArtifactSizeBytes > 0 {
		limit = pc.Config.MaxDockerArtifactSizeBytes
	}
	if limit <= 0 {
		limit = 512 * 1024 * 1024
	}

	payload, filename, releaseBundle, err := fetchArtifact(ctx, pc, meta, limit)
	if err != nil {
		return Fail(fmt.Sprintf("Артефакт не скачан: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Повторите заявку позже: артефакт получить не удалось."), nil
	}

	digest := sha256.Sum256(payload)
	sha := hex.EncodeToString(digest[:])

	// Контрольная сумма из реестра сверяется до записи в хранилище: артефакт,
	// перезалитый в реестре между запросом метаданных и скачиванием, не должен
	// уехать дальше по конвейеру.
	checksumNote := "реестр не сообщил контрольную сумму"
	if releaseBundle {
		checksumNote = "контрольные суммы файлов релиза проверены до упаковки"
	} else if meta.Checksum != "" && meta.ChecksumAlgo != "" {
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

func downloadGitMirror(ctx context.Context, pc *Context) (StepOutcome, error) {
	if pc.Deps.GitMirror == nil {
		return Fail("Git-репозиторий не зеркалирован: интеграция с внутренним GitLab не настроена.").
			WithStatus("failed", "failed").
			WithNextAction("Администратор: настройте раздел «Git-модерация» и перезапустите проверку."), nil
	}
	maintainer := ""
	if pc.Author != nil {
		maintainer = pc.Author.Username
		if pc.Author.GitlabUsername != nil && strings.TrimSpace(*pc.Author.GitlabUsername) != "" {
			maintainer = strings.TrimSpace(*pc.Author.GitlabUsername)
		}
	}
	result, err := pc.Deps.GitMirror.Mirror(ctx, pc.Package.DisplayName, maintainer)
	if err != nil {
		return Fail(fmt.Sprintf("Git-репозиторий не зеркалирован во внутренний GitLab: %v", err)).
			WithStatus("failed", "failed").
			WithNextAction("Проверьте доступность исходного репозитория и сервисные токены Git-модерации."), nil
	}
	if strings.TrimSpace(maintainer) == "" || !result.MaintainerAssigned {
		return Fail(fmt.Sprintf(
			"Репозиторий зеркалирован, но пользователь %q не найден во внутреннем GitLab и не назначен Maintainer.",
			maintainer)).WithDetails(map[string]any{
			"project_url": result.ProjectURL, "maintainer": maintainer,
			"maintainer_assigned": false,
		}).WithStatus("failed", "failed").WithNextAction(
			"Подключите пользователю GitLab в профиле или синхронизируйте его логин с внутренним GitLab, затем повторите проверку."), nil
	}
	artifact, err := pc.Deps.Repo.GetOrCreateArtifact(ctx, pc.Version.ID, "repository.git")
	if err != nil {
		return StepOutcome{}, err
	}
	if err := pc.Deps.Repo.SetArtifactExternalReference(
		ctx, artifact.ID, result.SourceURL, result.ProjectURL,
	); err != nil {
		return StepOutcome{}, err
	}
	return Pass(fmt.Sprintf(
		"Репозиторий зеркалирован во внутренний GitLab: %d веток, %d тегов. Рабочая ветка: %s.",
		result.Branches, result.Tags, result.PTBranch)).WithDetails(map[string]any{
		"source_url": result.SourceURL, "project_url": result.ProjectURL,
		"project_id": result.ProjectID, "target_path": result.TargetPath,
		"default_branch": result.DefaultBranch, "protected_branch": result.PTBranch,
		"branches": result.Branches, "tags": result.Tags,
		"created": result.Created, "forced": result.Forced, "lfs_supported": result.LFSSupported,
		"maintainer": result.Maintainer, "maintainer_assigned": result.MaintainerAssigned,
	}), nil
}

// fetchArtifact получает байты артефакта.
//
// Два пути, и выбор между ними — по тому, умеет ли менеджер забирать артефакт
// сам. Большинству это не нужно: артефакт лежит по ссылке одним файлом, и
// обычного GET достаточно. Docker и git — исключения по природе предмета: у
// первого артефакт собирается из блобов по манифесту, у второго его как файла
// вообще не существует, пока не создан. Maven и PyPI тоже используют
// Downloader, потому что один релиз состоит из нескольких файлов
// (см. registry.Downloader и registry.ReleaseBundleDownloader).
func fetchArtifact(
	ctx context.Context, pc *Context, meta registry.Metadata, limit int64,
) ([]byte, string, bool, error) {
	plugin, err := pc.Plugin()
	if err != nil {
		return nil, "", false, err
	}
	if downloader, ok := plugin.(registry.Downloader); ok {
		payload, filename, err := downloader.Download(ctx, pc.Ref(), limit)
		if err != nil {
			return nil, "", false, err
		}
		if filename == "" {
			filename = meta.ArtifactFilename
		}
		_, releaseBundle := plugin.(registry.ReleaseBundleDownloader)
		return payload, defaultFilename(filename, pc), releaseBundle, nil
	}

	if meta.ArtifactURL == "" {
		return nil, "", false, fmt.Errorf("реестр не сообщил адрес артефакта — скачивать нечего")
	}
	payload, err := pc.Deps.Fetch.Fetch(ctx, meta.ArtifactURL, limit)
	if err != nil {
		return nil, "", false, err
	}
	return payload, defaultFilename(meta.ArtifactFilename, pc), false, nil
}

// defaultFilename — имя файла, если менеджер его не сообщил. Пустое имя
// означало бы путь в хранилище, заканчивающийся слешем, то есть запись в
// каталог вместо файла.
func defaultFilename(filename string, pc *Context) string {
	if strings.TrimSpace(filename) != "" {
		return filename
	}
	return fmt.Sprintf("%s-%s", pc.Package.Name, pc.Version.RawVersion)
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
