package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/config"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// База пакетов и справочник менеджеров. Порт backend/app/api/v1/packages.go.
//
// Формат ответов совпадает с python-версией дословно: эти маршруты читает тот
// же фронтенд, и он переезда не заметит.

// PackagesHandler — зависимости маршрутов базы пакетов.
type PackagesHandler struct {
	Repo     *repo.Repo
	Registry *registry.Registry
	Cfg      *config.Config
	// Decisions — сервис решений, нужен отзыву пакета. nil — маршрут отзыва
	// не подключается: отдать его неработающим хуже, чем не отдать совсем.
	Decisions *decisions.Service
	// Artifacts — артефактори, откуда снимается отозванный пакет. nil
	// допустим: сервис поднимается и без него, и тогда отзыв меняет только
	// статус, о чём ответ говорит прямо.
	Artifacts artifactstore.Store
	Now       func() time.Time
}

func (h *PackagesHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// MountPackages подключает справочник менеджеров и базу пакетов. Всё закрыто
// проверкой токена: в базе видно, какие пакеты и версии тянет компания.
// Группа с полными путями, а не Route("/api/v1"): под этим префиксом уже
// смонтированы /auth и /requests, и chi на попытку смонтировать туда же второй
// обработчик падает паникой при сборке роутера.
func MountPackages(r chi.Router, h *PackagesHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/api/v1/managers", h.Managers)
		sub.Get("/api/v1/managers/detect", h.DetectManager)
		sub.Get("/api/v1/packages", h.Search)
		sub.Get("/api/v1/packages/{versionID}", h.Version)
		// «Найти пакет»: отвечает не «есть в базе», а можно ли ставить.
		sub.Post("/api/v1/packages/check", h.Check)
	})
	// Отзыв — только DevSecOps и админу: он отменяет ранее принятое решение и
	// снимает пакет с публикации у всех сразу.
	if h.Decisions != nil {
		r.Group(func(sub chi.Router) {
			sub.Use(a.Authenticate)
			sub.Use(RequireRoles("admin", "devsecops"))
			sub.Post("/api/v1/packages/{versionID}/revoke", h.Revoke)
		})
	}
}

// Managers — GET /api/v1/managers. Порядок совпадает с python-версией
// (pypi, npm, go, nuget): по нему строится выпадающий список.
func (h *PackagesHandler) Managers(w http.ResponseWriter, r *http.Request) {
	plugins := h.Registry.Plugins()
	out := make([]map[string]any, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, map[string]any{
			"code":         p.Code(),
			"title":        p.Title(),
			"entry_format": p.EntryFormat(),
			// У git/files нет файлов зависимостей. Нулевой slice нельзя
			// сериализовать как null: интерфейс обращается с полем как со
			// списком, а контракт /managers обещает именно массив.
			"dependency_files": listOrEmpty(p.DependencyFiles()),
			"osv_ecosystem":    p.OSVEcosystem(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// DetectManager — GET /api/v1/managers/detect?filename=go.sum.
// manager = null, если файл ничей: это подсказка интерфейсу, а не ошибка.
func (h *PackagesHandler) DetectManager(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if strings.TrimSpace(filename) == "" {
		writeError(w, r, errValidation("Параметр filename обязателен"))
		return
	}
	var manager any
	if code := h.Registry.DetectByFile(filename); code != "" {
		manager = code
	}
	writeJSON(w, http.StatusOK, map[string]any{"filename": filename, "manager": manager})
}

// Search — GET /api/v1/packages. Поиск по базе пакетов.
func (h *PackagesHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, err := intParam(q.Get("limit"), 50)
	if err != nil {
		writeError(w, r, errValidation("Параметр limit должен быть числом"))
		return
	}
	if limit > 200 {
		writeError(w, r, errValidation("Параметр limit не больше 200"))
		return
	}
	offset, err := intParam(q.Get("offset"), 0)
	if err != nil || offset < 0 {
		writeError(w, r, errValidation("Параметр offset должен быть неотрицательным числом"))
		return
	}

	rows, total, err := h.Repo.SearchVersions(r.Context(), repo.VersionSearch{
		Query: q.Get("q"), Manager: q.Get("manager"),
		Version: q.Get("version"), Status: q.Get("status"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeError(w, r, errInternal("Не удалось выполнить поиск по базе пакетов").Because(err))
		return
	}

	items := make([]map[string]any, 0, len(rows))
	for i := range rows {
		view, err := h.versionSummary(r, &rows[i])
		if err != nil {
			writeError(w, r, errInternal("Не удалось собрать карточку пакета").Because(err))
			return
		}
		items = append(items, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total, "limit": limit, "offset": offset, "items": items,
	})
}

// Version — GET /api/v1/packages/{versionID}. Карточка версии пакета.
func (h *PackagesHandler) Version(w http.ResponseWriter, r *http.Request) {
	versionID, ok := pathInt64(w, r, "versionID")
	if !ok {
		return
	}
	row, err := h.Repo.GetVersionRow(r.Context(), versionID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать карточку пакета").Because(err))
		return
	}
	if row == nil {
		writeError(w, r, errNotFound("Версия пакета #"+strconv.FormatInt(versionID, 10)+" не найдена"))
		return
	}
	view, err := h.versionSummary(r, row)
	if err != nil {
		writeError(w, r, errInternal("Не удалось собрать карточку пакета").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// versionSummary — порт services.packages.version_summary.
func (h *PackagesHandler) versionSummary(r *http.Request, row *repo.VersionRow) (map[string]any, error) {
	v := row.Version
	vulns, err := h.Repo.ListVulnerabilities(r.Context(), v.ID)
	if err != nil {
		return nil, err
	}
	artifacts, err := h.Repo.ListArtifacts(r.Context(), v.ID)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"id":               v.ID,
		"manager":          row.Manager,
		"name":             row.DisplayName,
		"normalized_name":  row.Name,
		"version":          v.RawVersion,
		"status":           v.Status,
		"license_spdx":     v.LicenseSPDX,
		"license_source":   v.LicenseSource,
		"published_at":     v.PublishedAt,
		"quarantine_until": v.QuarantineUntil,
		"approved_at":      v.ApprovedAt,
		"max_vuln_score":   v.MaxVulnScore,
		"status_reason":    v.StatusReason,
		"vulnerabilities":  vulnerabilityViews(vulns, true),
		"artifacts":        artifactViews(artifacts),
	}
	// Команда установки имеет смысл только у одобренного пакета: у остального
	// она вела бы в репозиторий, где артефакта нет.
	if v.Status == "approved" {
		if cmd := h.installCommand(row); cmd != "" {
			out["install_command"] = cmd
		}
	}
	return out, nil
}

// installCommand — готовая команда установки из внутреннего репозитория.
// Пустая строка, если менеджер неизвестен: это не повод ронять карточку.
func (h *PackagesHandler) installCommand(row *repo.VersionRow) string {
	plugin, err := h.Registry.Get(row.Manager)
	if err != nil {
		return ""
	}
	ref := registry.Ref{
		Manager: row.Manager, Name: row.Name, DisplayName: row.DisplayName,
		Version: row.Version.Version, RawVersion: row.Version.RawVersion,
	}
	installBaseURL, installRepo := h.Cfg.ArtifactInstallLocation(row.Manager)
	return plugin.InstallCommand(ref, installBaseURL, installRepo)
}

// vulnerabilityViews — уязвимости для выдачи. full=true — карточка пакета, у
// неё полей больше; false — карточка заявки (порт request_payload, там
// affected_ranges и index_version_id не отдаются).
func vulnerabilityViews(vulns []domain.Vulnerability, full bool) []map[string]any {
	out := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		item := map[string]any{
			"id":             v.ExternalID,
			"score":          v.Score,
			"cvss_vector":    v.CVSSVector,
			"severity":       v.Severity,
			"url":            v.URL,
			"summary":        v.Summary,
			"fixed_versions": listOrEmpty(v.FixedVersions),
		}
		if full {
			item["affected_ranges"] = v.AffectedRanges
			item["index_version_id"] = v.VulnIndexVersionID
		}
		out = append(out, item)
	}
	return out
}

func artifactViews(artifacts []domain.Artifact) []map[string]any {
	out := make([]map[string]any, 0, len(artifacts))
	for _, a := range artifacts {
		out = append(out, map[string]any{
			"filename":      a.Filename,
			"nexus_url":     a.NexusURL,
			"sha256":        a.SHA256,
			"size_bytes":    a.SizeBytes,
			"s3_key":        a.StagingPath,
			"s3_deleted_at": a.StagingClearedAt,
			"status":        a.Status,
		})
	}
	return out
}

func codeFindingViews(findings []domain.CodeFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"scanner":  f.Scanner,
			"rule_id":  f.RuleID,
			"severity": f.Severity,
			"message":  f.Message,
			"file":     f.FilePath,
			"line":     f.Line,
			"matched":  f.Matched,
		})
	}
	return out
}

// listOrEmpty — пустой список вместо null: фронтенд делает .map() по этим
// полям без проверки.
func listOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func intParam(raw string, fallback int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}
