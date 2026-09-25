package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
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
			sub.Post("/{requestID}/items/{itemID}/retry", h.RetryItem)
		}
		sub.Post("/{requestID}/cancel", h.Cancel)
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
			"can_restart":        h.canRestartItem(r, req, &item),
		}
		// Дерево зависимостей: кто притащил этот пакет и по какому требованию.
		// Юристу и DevSecOps это меняет разговор: «эта GPL пришла через вот
		// тот пакет» — не то же самое, что «у нас в заявке GPL».
		itemTreeView(view, item.ParentItemID, item.Depth, item.RequiredRange)
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

	payload := map[string]any{
		"request_id":   req.ID,
		"manager":      req.Manager,
		"status":       req.Status,
		"status_title": statusTitle(req.Status),
		"approved":     allApproved,
		// can_cancel — можно ли закрыть заявку прямо сейчас и именно этому
		// пользователю. Решает сервер, а не интерфейс: правило одно и то же
		// (автор или администратор, есть что закрывать), и повторять его во
		// фронте значило бы завести второй источник правды, который начнёт
		// расходиться с маршрутом.
		"can_cancel":         h.canCancel(r, req, statusCounts),
		"author":             nilIfEmpty(author),
		"author_role":        req.AuthorRole,
		"reason":             req.Reason,
		"source":             req.Source,
		"origin_file":        req.OriginFile,
		"include_transitive": req.IncludeTransitive,
		"resolve_depth":      req.ResolveDepth,
		"resolve_summary":    req.ResolveSummary,
		"warnings":           listOrEmpty(req.Warnings),
		"created_at":         req.CreatedAt,
		"updated_at":         req.UpdatedAt,
		"summary":            requestSummary(len(packages), statusCounts),
		"packages":           packages,
	}
	payload["can_restart"] = false
	for _, item := range items {
		if h.canRestartItem(r, req, &item) {
			payload["can_restart"] = true
			break
		}
	}
	return payload, nil
}

func (h *RequestsHandler) canRestartItem(
	r *http.Request, req *domain.ModerationRequest, item *domain.RequestItem,
) bool {
	user, ok := CurrentUser(r.Context())
	if !ok || (req.AuthorID != user.ID && !user.HasRole("admin", "devsecops")) {
		return false
	}
	switch item.Status {
	case "approved", "rejected", "revoked", "blacklisted", "cancelled", "queued":
		return false
	case "running":
		return h.Queue != nil && item.UpdatedAt.Before(time.Now().UTC().Add(-h.Queue.StaleAfter))
	default:
		return h.Queue != nil
	}
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
	installBaseURL, installRepo := h.Cfg.ArtifactInstallLocation(row.Manager)
	return plugin.InstallCommand(ref, installBaseURL, installRepo)
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
		"total":     total,
		"by_status": byStatus,
		// cancellable — сколько пакетов ещё можно закрыть. Считается по тому же
		// списку статусов, что и сам UPDATE в репозитории.
		"cancellable":       cancellableCount(counts),
		"cancelled":         counts["cancelled"],
		"approved":          counts["approved"],
		"awaiting_security": counts["awaiting_security"],
		"awaiting_legal":    counts["awaiting_legal"] + counts["license_claimed"],
		"quarantined":       counts["quarantined"],
		"rejected":          counts["rejected"] + counts["blacklisted"] + counts["revoked"],
		"failed":            counts["failed"],
	}
}

// cancellableCount — сколько пакетов заявки ещё можно закрыть.
func cancellableCount(counts map[string]int) int {
	total := 0
	for _, status := range repo.CancellableItemStatuses {
		total += counts[status]
	}
	return total
}

// canCancel — доступна ли этому пользователю кнопка закрытия заявки. Условие
// то же, что проверяет сам маршрут Cancel.
func (h *RequestsHandler) canCancel(r *http.Request, req *domain.ModerationRequest, counts map[string]int) bool {
	user, ok := CurrentUser(r.Context())
	if !ok {
		return false
	}
	if req.AuthorID != user.ID && !user.HasRole("admin") {
		return false
	}
	return cancellableCount(counts) > 0
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
			if err := h.Queue.Restart(r.Context(), item.ID, "db_check"); err != nil {
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

type retryItemBody struct {
	FromStep string `json:"from_step"`
}

// RetryItem — POST /api/v1/requests/{requestID}/items/{itemID}/retry.
//
// from_step означает «повторить этот шаг и все следующие». Запуск одного
// шага в отрыве от последующих был бы опасен: новый результат sandbox или
// лицензии обязан заново повлиять на решение о публикации.
func (h *RequestsHandler) RetryItem(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	itemID, ok := pathInt64(w, r, "itemID")
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
	if req.AuthorID != user.ID && !user.HasRole("admin", "devsecops") {
		writeError(w, r, errForbidden(
			"Перезапустить проверку может её автор, DevSecOps или администратор"))
		return
	}
	item, err := h.Repo.GetRequestItem(r.Context(), itemID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать пакет заявки").Because(err))
		return
	}
	if item == nil || item.RequestID != requestID {
		writeError(w, r, errNotFound("Пакет не найден в этой заявке"))
		return
	}

	body := retryItemBody{FromStep: "db_check"}
	if r.Body != nil {
		err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
		if err != nil && !errors.Is(err, io.EOF) {
			writeError(w, r, errBadRequest("Тело перезапуска не разобрано как JSON"))
			return
		}
	}
	if body.FromStep == "" {
		body.FromStep = "db_check"
	}
	if !pipeline.IsActiveStep(body.FromStep) {
		writeError(w, r, errValidation("Неизвестный или отключённый шаг: "+body.FromStep))
		return
	}
	if err := h.Queue.Restart(r.Context(), itemID, body.FromStep); err != nil {
		switch {
		case errors.Is(err, queue.ErrActive):
			writeError(w, r, errConflict(
				"Пакет уже проверяется живым воркером. Дождитесь окончания текущего шага или его таймаута."))
		case errors.Is(err, queue.ErrTerminal):
			writeError(w, r, errConflict(
				"Итоговое решение по пакету нельзя отменить техническим перезапуском."))
		default:
			writeError(w, r, errInternal("Пакет не поставлен на повторную проверку").Because(err))
		}
		return
	}
	if _, err := h.Repo.RecomputeRequestStatus(r.Context(), requestID); err != nil {
		defaultLogger.Printf("[%s] статус заявки #%d не пересчитан: %v",
			RequestID(r.Context()), requestID, err)
	}
	payload, err := h.requestPayload(r, mustReread(r, h, requestID, req))
	if err != nil {
		writeError(w, r, errInternal("Не удалось собрать карточку заявки").Because(err))
		return
	}
	payload["restarted_item"] = itemID
	payload["from_step"] = body.FromStep
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

// Cancel — POST /api/v1/requests/{requestID}/cancel.
//
// Автор закрывает свою заявку: пакеты больше не нужны (взяли другую
// библиотеку, переписали код, ошиблись версией). Без этого заявка висела в
// очереди роли и выглядела как работа, которую кто-то должен сделать, а
// закрыть её было нечем.
//
// Это НЕ отклонение: `rejected` — решение роли («нельзя»), `cancelled` —
// отказ автора («уже не нужно»). Путать их в отчётности нельзя, поэтому
// статус отдельный.
//
// Отменяются только незавершённые пакеты. Уже одобренный, отклонённый или
// отозванный не трогаем: отмена не отзывает чужое решение и не снимает
// опубликованный пакет (для этого есть revoke).
func (h *RequestsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут отмены не закрыт проверкой токена"))
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
	// Закрыть заявку может только её автор (и администратор — для поддержки).
	// DevSecOps и юрист сюда не входят СОЗНАТЕЛЬНО: у них есть отклонение,
	// которое означает решение по существу, и подменять его отменой от чужого
	// имени нельзя — в журнале исчезло бы, кто на самом деле отказал.
	if req.AuthorID != user.ID && !user.HasRole("admin") {
		writeError(w, r, errForbidden("Закрыть заявку может её автор или администратор"))
		return
	}

	cancelled, err := h.Repo.CancelRequestItems(r.Context(), requestID)
	if err != nil {
		// Ошибка уровня схемы называет себя сама: общее «Заявка не закрыта»
		// бесполезно — пользователь видит ошибку и идти ему с ней некуда, а
		// причина в развёртывании, а не в заявке.
		if schemaErr := schemaError(err); schemaErr != nil {
			writeError(w, r, schemaErr)
			return
		}
		writeError(w, r, errInternal("Заявка не закрыта").Because(err))
		return
	}
	if cancelled == 0 {
		// Отменять нечего — но причины разные, и ответ обязан их различать:
		// «уже закрыта» это повторное нажатие кнопки, а «всё завершено» —
		// попытка отозвать готовое решение.
		writeError(w, r, cancelNothingToDo(r.Context(), h, requestID))
		return
	}

	if _, err := h.Repo.RecomputeRequestStatus(r.Context(), requestID); err != nil {
		// Статус заявки — свёртка статусов пакетов; без пересчёта заявка
		// осталась бы «в обработке» с отменёнными пакетами внутри.
		defaultLogger.Printf("[%s] статус заявки #%d не пересчитан: %v",
			RequestID(r.Context()), requestID, err)
	}
	h.auditCancel(r, requestID, user, cancelled)

	payload, err := h.requestPayload(r, mustReread(r, h, requestID, req))
	if err != nil {
		writeError(w, r, errInternal("Не удалось собрать карточку заявки").Because(err))
		return
	}
	payload["cancelled"] = cancelled
	writeJSON(w, http.StatusOK, payload)
}

// cancelNothingToDo объясняет, почему отменять нечего.
func cancelNothingToDo(ctx context.Context, h *RequestsHandler, requestID int64) *Error {
	statuses, err := h.Repo.ItemStatusByRequest(ctx, requestID)
	if err != nil {
		return errInternal("Заявка не закрыта").Because(err)
	}
	if len(statuses) == 0 {
		return &Error{Code: "conflict", Status: http.StatusConflict,
			Message: "В заявке нет пакетов — закрывать нечего"}
	}
	allCancelled := true
	for _, status := range statuses {
		if status != "cancelled" {
			allCancelled = false
			break
		}
	}
	if allCancelled {
		return &Error{Code: "conflict", Status: http.StatusConflict,
			Message: "Заявка уже закрыта"}
	}
	return &Error{Code: "conflict", Status: http.StatusConflict,
		Message: "Закрывать нечего: по всем пакетам заявки проверка уже завершена. " +
			"Опубликованный пакет снимает DevSecOps (отзыв версии)."}
}

// auditCancel пишет журнал. Отдельно от обработчика: отказ автора — событие,
// которое потом объясняет, почему заявка не доехала до решения роли.
func (h *RequestsHandler) auditCancel(r *http.Request, requestID int64, user *domain.User, cancelled int) {
	entityID := strconv.FormatInt(requestID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: "request_cancelled", EntityType: "moderation_request", EntityID: &entityID,
		NewValue: map[string]any{"cancelled_items": cancelled},
		Source:   "ui", IP: ClientIP(r), CreatedAt: time.Now().UTC(),
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
		// Журнал не должен ронять действие: заявка уже закрыта, и отвечать
		// ошибкой означало бы предложить нажать кнопку ещё раз.
		defaultLogger.Printf("[%s] аудит закрытия заявки #%d не записан: %v",
			RequestID(r.Context()), requestID, err)
	}
}
