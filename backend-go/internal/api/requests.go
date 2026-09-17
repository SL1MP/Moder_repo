package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/queue"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
)

// Заявки: список и карточка. Порт маршрутов чтения из
// backend/app/api/v1/requests.py и services/requests_service.request_payload.
//
// Права: разработчик видит свои заявки, DevSecOps/юрист/админ — все. Проверка
// здесь, а не только в интерфейсе: маршрут можно позвать и мимо него.

// RequestsHandler — зависимости маршрутов заявок.
type RequestsHandler struct {
	Repo     *repo.Repo
	Registry *registry.Registry
	Cfg      *config.Config
	// Requests — разбор и создание заявок. nil — маршрут создания не
	// подключается (см. MountRequests): отдавать 500 на кнопку «Добавить
	// пакеты» хуже, чем честно не иметь этого маршрута.
	Requests *requests.Service
	// Queue — очередь конвейера. nil — пакеты заводятся в статусе `queued`,
	// но воркеры не будятся: их подберёт ближайший опрос.
	Queue *queue.Queue
}

// MountRequests подключает маршруты заявок.
func MountRequests(r chi.Router, h *RequestsHandler, a *Auth) {
	r.Route("/api/v1/requests", func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/", h.List)
		sub.Get("/{requestID}", h.Get)
		if h.Requests != nil {
			sub.Post("/", h.Create)
		}
		if h.Queue != nil {
			sub.Post("/{requestID}/retry", h.Retry)
		}
	})
}

// canSeeAllRequests — видит ли пользователь чужие заявки. Порт условия из
// list_requests и _check_access: очередь DevSecOps и юриста бессмысленна, если
// в ней видно только свои заявки.
func canSeeAllRequests(user *domain.User) bool {
	return user.HasRole("admin", "devsecops", "legal")
}

// List — GET /api/v1/requests.
func (h *RequestsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут списка заявок не закрыт проверкой токена"))
		return
	}
	q := r.URL.Query()
	limit, err := intParam(q.Get("limit"), 50)
	if err != nil || limit <= 0 {
		writeError(w, r, errValidation("Параметр limit должен быть положительным числом"))
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

	filter := repo.RequestFilter{
		Status: q.Get("status"), Manager: q.Get("manager"),
		Limit: limit, Offset: offset,
	}
	// mine=true просят явно; без прав на чужие заявки фильтр по автору
	// ставится в любом случае.
	if q.Get("mine") == "true" || !canSeeAllRequests(user) {
		id := user.ID
		filter.AuthorID = &id
	}

	rows, err := h.Repo.ListRequests(r.Context(), filter)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить список заявок").Because(err))
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"request_id":   row.Request.ID,
			"manager":      row.Request.Manager,
			"status":       row.Request.Status,
			"status_title": statusTitle(row.Request.Status),
			"author":       row.Author,
			"reason":       row.Request.Reason,
			"created_at":   row.Request.CreatedAt,
			"total":        row.Total,
			"approved":     row.Approved,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Get — GET /api/v1/requests/{requestID}. Полный агрегат заявки.
//
// Параметр wait=true из python-версии не перенесён намеренно: там он держит
// HTTP-соединение до получаса, опрашивая базу раз в секунду. Это не ожидание,
// а занятый воркер; CI должен опрашивать статус сам.
func (h *RequestsHandler) Get(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут заявки не закрыт проверкой токена"))
		return
	}

	req, err := h.Repo.GetModerationRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать заявку").Because(err))
		return
	}
	if req == nil {
		writeError(w, r, errNotFound("Заявка #"+strconv.FormatInt(requestID, 10)+" не найдена"))
		return
	}
	if !canSeeAllRequests(user) && req.AuthorID != user.ID {
		writeError(w, r, errForbidden("Заявка доступна её автору, DevSecOps, юристам и администратору"))
		return
	}

	payload, err := h.requestPayload(r, req)
	if err != nil {
		writeError(w, r, errInternal("Не удалось собрать карточку заявки").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// requestPayload — порт requests_service.request_payload.
//
// Данные по всем пакетам заявки берутся пачками, а не по пакету за запрос: в
// заявке их до двухсот (MAX_PACKAGES_PER_REQUEST), и запрос на пакет превратил
// бы открытие карточки в тысячу обращений к базе.
func (h *RequestsHandler) requestPayload(r *http.Request, req *domain.ModerationRequest) (map[string]any, error) {
	ctx := r.Context()
	items, err := h.Repo.ListItemsByRequest(ctx, req.ID)
	if err != nil {
		return nil, err
	}

	itemIDs := make([]int64, 0, len(items))
	versionIDs := make([]int64, 0, len(items))
	for _, item := range items {
		itemIDs = append(itemIDs, item.ID)
		versionIDs = append(versionIDs, item.PackageVersionID)
	}

	steps, err := h.Repo.StepsByItems(ctx, itemIDs)
	if err != nil {
		return nil, err
	}
	versions, err := h.Repo.VersionsByIDs(ctx, versionIDs)
	if err != nil {
		return nil, err
	}
	vulns, err := h.Repo.VulnerabilitiesByVersions(ctx, versionIDs)
	if err != nil {
		return nil, err
	}
	findings, err := h.Repo.CodeFindingsByVersions(ctx, versionIDs)
	if err != nil {
		return nil, err
	}
	author, err := h.Repo.AuthorOf(ctx, req.ID)
	if err != nil {
		return nil, err
	}

	packages := make([]map[string]any, 0, len(items))
	statusCounts := map[string]int{}
	allApproved := len(items) > 0
	for _, item := range items {
		version := versions[item.PackageVersionID]
		itemSteps := steps[item.ID]

		view := map[string]any{
			"id":                 item.ID,
			"package_version_id": item.PackageVersionID,
			"name":               item.RequestedName,
			"version":            item.RequestedVersion,
			"dependency_kind":    item.DependencyKind,
			"status":             item.Status,
			"status_title":       statusTitle(item.Status),
			// Какие решения ролей ещё не получены. Статус у пакета один, а
			// ждать он может двух сразу — интерфейс рисует блоки решений по
			// этому списку, иначе более блокирующий статус скрыл бы второй.
			"pending":            listOrEmpty(pipeline.PendingBlockers(itemSteps)),
			"current_step":       item.CurrentStep,
			"current_step_title": stepTitleOf(item.CurrentStep),
			"blocked_reason":     item.BlockedReason,
			"next_action":        item.NextAction,
			"waiting_since":      item.WaitingSince,
			"finished_at":        item.FinishedAt,
			"license_spdx":       version.Version.LicenseSPDX,
			"quarantine_until":   version.Version.QuarantineUntil,
			"max_vuln_score":     version.Version.MaxVulnScore,
			"vulnerabilities":    vulnerabilityViews(vulns[item.PackageVersionID], false),
			"code_findings":      codeFindingViews(findings[item.PackageVersionID]),
			"steps":              stepViews(itemSteps),
		}
		if version.Version.Status == "approved" {
			if cmd := h.installCommand(version); cmd != "" {
				view["install_command"] = cmd
			}
		}
		packages = append(packages, view)

		statusCounts[item.Status]++
		if item.Status != "approved" {
			allApproved = false
		}
	}

	return map[string]any{
		"request_id":         req.ID,
		"manager":            req.Manager,
		"status":             req.Status,
		"status_title":       statusTitle(req.Status),
		"approved":           allApproved,
		"author":             nilIfEmpty(author),
		"author_role":        req.AuthorRole,
		"reason":             req.Reason,
		"source":             req.Source,
		"origin_file":        req.OriginFile,
		"include_transitive": req.IncludeTransitive,
		"warnings":           listOrEmpty(req.Warnings),
		"created_at":         req.CreatedAt,
		"updated_at":         req.UpdatedAt,
		"summary":            requestSummary(len(packages), statusCounts),
		"packages":           packages,
	}, nil
}

func (h *RequestsHandler) installCommand(row repo.VersionRow) string {
	plugin, err := h.Registry.Get(row.Manager)
	if err != nil {
		return ""
	}
	ref := registry.Ref{
		Manager: row.Manager, Name: row.Name, DisplayName: row.DisplayName,
		Version: row.Version.Version, RawVersion: row.Version.RawVersion,
	}
	return plugin.InstallCommand(ref, h.Cfg.ArtifactBaseURL, h.Cfg.ArtifactRepo(row.Manager))
}

// requestSummary — сводка по пакетам заявки. Порт _summary: несколько статусов
// схлопываются в одну строку сводки, потому что для читателя «отклонён»,
// «в blacklist» и «отозван» — одно и то же.
func requestSummary(total int, counts map[string]int) map[string]any {
	byStatus := map[string]int{}
	for status, n := range counts {
		byStatus[status] = n
	}
	return map[string]any{
		"total":             total,
		"by_status":         byStatus,
		"approved":          counts["approved"],
		"awaiting_security": counts["awaiting_security"],
		"awaiting_legal":    counts["awaiting_legal"] + counts["license_claimed"],
		"quarantined":       counts["quarantined"],
		"rejected":          counts["rejected"] + counts["blacklisted"] + counts["revoked"],
		"failed":            counts["failed"],
	}
}

// stepViews — снимок конвейера для карточки. Порт runner.step_snapshot:
// отдаются ВСЕ девять шагов, включая те, до которых прогон не дошёл, — иначе
// в карточке не видно, что ещё впереди.
func stepViews(steps []domain.PipelineStep) []map[string]any {
	byCode := make(map[string]domain.PipelineStep, len(steps))
	for _, s := range steps {
		byCode[s.StepCode] = s
	}
	out := make([]map[string]any, 0, len(domain.StepCodes))
	for order, code := range domain.StepCodes {
		view := map[string]any{
			"code": code, "order": order, "title": domain.StepTitles[code],
			"result": "pending", "message": nil, "details": nil,
			"started_at": nil, "finished_at": nil,
		}
		if s, ok := byCode[code]; ok {
			view["result"] = s.Result
			view["message"] = s.Message
			view["details"] = s.Details
			view["started_at"] = s.StartedAt
			view["finished_at"] = s.FinishedAt
		}
		out = append(out, view)
	}
	return out
}

func statusTitle(status string) string {
	if title, ok := domain.StatusTitles[status]; ok {
		return title
	}
	return status
}

// stepTitleOf — название текущего шага. null, если шага нет: python-версия
// отдаёт здесь None, и интерфейс на это рассчитывает.
func stepTitleOf(code *string) any {
	if code == nil {
		return nil
	}
	if title, ok := domain.StepTitles[*code]; ok {
		return title
	}
	return nil
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// Retry — POST /api/v1/requests/{requestID}/retry.
//
// Перезапускаются только упавшие пакеты: перезапуск уже одобренного отозвал бы
// решение, а перезапуск ждущего роли обнулил бы ожидание.
func (h *RequestsHandler) Retry(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут перезапуска не закрыт проверкой токена"))
		return
	}
	req, err := h.Repo.GetModerationRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать заявку").Because(err))
		return
	}
	if req == nil {
		writeError(w, r, errNotFound("Заявка #"+strconv.FormatInt(requestID, 10)+" не найдена"))
		return
	}
	if !canSeeAllRequests(user) && req.AuthorID != user.ID {
		writeError(w, r, errForbidden("Заявка доступна её автору, DevSecOps, юристам и администратору"))
		return
	}
	if !user.HasRole("admin", "devsecops") && req.AuthorID != user.ID {
		writeError(w, r, errForbidden(
			"Перезапустить заявку может её автор, DevSecOps или администратор"))
		return
	}

	items, err := h.Repo.ListItemsByRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, r, errInternal("Пакеты заявки не прочитаны").Because(err))
		return
	}
	restarted := 0
	for _, item := range items {
		if item.Status != "failed" {
			continue
		}
		// С начала, а не с прежнего шага: причина падения может быть выше по
		// конвейеру, чем место, где оно проявилось.
		if h.Queue != nil {
			if err := h.Queue.Enqueue(r.Context(), item.ID, ""); err != nil {
				writeError(w, r, errInternal("Пакет не поставлен в очередь").Because(err))
				return
			}
		}
		restarted++
	}
	if restarted > 0 {
		if _, err := h.Repo.RecomputeRequestStatus(r.Context(), requestID); err != nil {
			defaultLogger.Printf("[%s] статус заявки #%d не пересчитан: %v",
				RequestID(r.Context()), requestID, err)
		}
	}

	payload, err := h.requestPayload(r, mustReread(r, h, requestID, req))
	if err != nil {
		writeError(w, r, errInternal("Не удалось собрать карточку заявки").Because(err))
		return
	}
	payload["restarted"] = restarted
	writeJSON(w, http.StatusOK, payload)
}

// mustReread перечитывает заявку после перезапуска; при ошибке возвращает то,
// что было — карточка важнее идеальной свежести одного поля.
func mustReread(r *http.Request, h *RequestsHandler, requestID int64, fallback *domain.ModerationRequest) *domain.ModerationRequest {
	fresh, err := h.Repo.GetModerationRequest(r.Context(), requestID)
	if err != nil || fresh == nil {
		return fallback
	}
	return fresh
}
