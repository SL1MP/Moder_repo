package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/repo"
	"moderation/internal/storage"
)

type SBOMsHandler struct {
	Repo    *repo.Repo
	Storage storage.Store
}

type sbomView struct {
	Manager     string    `json:"manager"`
	Platform    string    `json:"platform,omitempty"`
	Filename    string    `json:"filename"`
	Format      string    `json:"format"`
	SpecVersion string    `json:"spec_version"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
	DownloadURL string    `json:"download_url"`
}

func MountSBOMs(r chi.Router, h *SBOMsHandler, a *Auth) {
	r.Route("/api/v1/request-items/{itemID}/sboms", func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/", h.List)
		sub.Get("/{file}", h.Download)
	})
}

func (h *SBOMsHandler) List(w http.ResponseWriter, r *http.Request) {
	itemID, ok := pathInt64(w, r, "itemID")
	if !ok { return }
	docs, err := h.Repo.ListSBOMDocuments(r.Context(), itemID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить список SBOM").Because(err))
		return
	}
	views := make([]sbomView, 0, len(docs))
	for _, d := range docs {
		views = append(views, sbomView{
			Manager: d.Manager, Platform: d.Platform, Filename: d.Filename,
			Format: d.Format, SpecVersion: d.SpecVersion, SizeBytes: d.SizeBytes,
			SHA256: d.SHA256, CreatedAt: d.CreatedAt,
			DownloadURL: fmt.Sprintf("/api/v1/request-items/%d/sboms/%s", itemID, url.PathEscape(d.Filename)),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_item_id": itemID, "sboms": views})
}

func (h *SBOMsHandler) Download(w http.ResponseWriter, r *http.Request) {
	itemID, ok := pathInt64(w, r, "itemID")
	if !ok { return }
	filename := chi.URLParam(r, "file")
	doc, err := h.Repo.GetSBOMDocument(r.Context(), itemID, filename)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить SBOM").Because(err))
		return
	}
	if doc == nil {
		writeError(w, r, errNotFound("SBOM не найден"))
		return
	}
	body, err := h.Storage.Get(r.Context(), doc.StorageKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, r, errNotFound("Файл SBOM отсутствует в хранилище").Because(err))
			return
		}
		writeError(w, r, errUpstream("Хранилище SBOM недоступно").Because(err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, doc.Filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
