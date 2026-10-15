package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"moderation/internal/config"
	"moderation/internal/domain"
)

// ArtifactCatalogSyncStatus возвращает состояние самого обхода. Это не
// статус пакетов: найденные версии остаются обычными approved-записями.
func (h *AdminHandler) ArtifactCatalogSyncStatus(w http.ResponseWriter, r *http.Request) {
	if h.Repo == nil {
		writeError(w, r, errInternal("База данных каталога не подключена"))
		return
	}
	run, err := h.Repo.LatestCatalogSync(r.Context())
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать состояние синхронизации").Because(err))
		return
	}
	managers := h.catalogManagers()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":             h.Cfg != nil && h.Cfg.MaintenanceEnabled && len(managers) > 0,
		"maintenance_enabled": h.Cfg != nil && h.Cfg.MaintenanceEnabled,
		"managers":            managers,
		"available_managers":  config.ArtifactCatalogManagers(),
		"last_run":            run,
	})
}

// StartArtifactCatalogSync ставит полный обход в долговечную очередь
// Postgres. HTTP-запрос сразу завершается, поэтому импорт большой
// корпоративной базы не создаёт 502 у nginx.
func (h *AdminHandler) StartArtifactCatalogSync(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут синхронизации не закрыт проверкой токена"))
		return
	}
	managers := h.catalogManagers()
	var payload struct {
		Managers []string `json:"managers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, errValidation("Ожидается JSON {managers: [...]} ").Because(err))
		return
	}
	if len(payload.Managers) > 0 {
		allowed, seen := config.ArtifactCatalogManagers(), map[string]bool{}
		managers = managers[:0]
		for _, manager := range payload.Managers {
			manager = strings.ToLower(strings.TrimSpace(manager))
			if manager == "" || seen[manager] {
				continue
			}
			if !domain.Contains(allowed, manager) {
				writeError(w, r, errValidation("Менеджер "+manager+" не поддерживает синхронизацию каталога"))
				return
			}
			seen[manager] = true
			managers = append(managers, manager)
		}
	}
	if h.Cfg == nil || !h.Cfg.MaintenanceEnabled {
		writeError(w, r, errValidation("Включите MAINTENANCE_ENABLED: синхронизацию выполняет worker"))
		return
	}
	if len(managers) == 0 {
		writeError(w, r, errValidation("Сначала задайте ARTIFACT_CATALOG_SYNC_MANAGERS"))
		return
	}
	run, err := h.Repo.EnqueueCatalogSync(r.Context(), "manual", managers, &user.ID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось поставить синхронизацию в очередь").Because(err))
		return
	}
	entityID := strconv.FormatInt(run.ID, 10)
	_ = h.Repo.InsertAuditLog(r.Context(), domain.AuditLog{
		ActorID: &user.ID, ActorName: user.DisplayName(), ActorRole: firstRole(user.Roles),
		Action: "artifact_catalog_sync_requested", EntityType: "artifact_catalog_sync",
		EntityID: &entityID, NewValue: map[string]any{"managers": managers},
		Source: "ui", CreatedAt: h.now(),
	})
	writeJSON(w, http.StatusAccepted, run)
}

func (h *AdminHandler) catalogManagers() []string {
	if h.Cfg == nil {
		return []string{}
	}
	return append([]string(nil), h.Cfg.ArtifactCatalogSyncManagers...)
}

func firstRole(roles []string) *string {
	if len(roles) == 0 {
		return nil
	}
	return &roles[0]
}
