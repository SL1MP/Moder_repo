package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"moderation/internal/auth"
	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/requests"
	"moderation/internal/resolve"
)

// Создание заявки. Порт POST /api/v1/requests из
// backend/app/api/v1/requests.py.
//
// Два способа задать пакеты, оба через один адрес: JSON со списком записей и
// multipart с файлом зависимостей. Адрес один, потому что так его зовёт
// существующий фронтенд.

// Create — POST /api/v1/requests.
func (h *RequestsHandler) Create(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут создания заявки не закрыт проверкой токена"))
		return
	}
	// Завести пакет может любая роль, но роль нужна: учётка без ролей — это
	// почти всегда незаданный маппинг групп, а не «нет прав».
	if len(user.Roles) == 0 {
		writeError(w, r, errForbidden(
			"У учётной записи нет ни одной роли сервиса. Проверьте членство в группах каталога "+
				"и переменные ROLE_MAPPING_*"))
		return
	}

	in, inputErr := h.readCreateInput(r)
	if inputErr != nil {
		writeError(w, r, inputErr)
		return
	}

	parsed, err := h.Requests.Parse(r.Context(), in)
	if err != nil {
		writeError(w, r, createError(err))
		return
	}

	// Раскрытие идёт до создания заявки: завести пакеты, а потом дописать к
	// ним зависимости значит на секунду показать пользователю неполную
	// заявку и заставить конвейер дважды пересчитывать свёртку статусов.
	var walk *resolve.Result
	if in.IncludeTransitive {
		parsed, walk, err = h.Requests.Expand(r.Context(), parsed, h.resolveOptions(in.ResolveDepth))
		if err != nil {
			writeError(w, r, errBadGateway(
				"Не удалось раскрыть транзитивные зависимости: реестр не ответил").Because(err))
			return
		}
	}

	source := "api"
	if r.Header.Get("x-client") == "web" {
		source = "ui"
	}
	created, itemIDs, err := h.Requests.Create(r.Context(), parsed, requests.CreateInput{
		Author: user, AuthorRole: auth.PrimaryRole(user.Roles),
		Reason: in.Reason, Source: source,
		IdempotencyKey:    r.Header.Get("Idempotency-Key"),
		OriginFile:        in.Filename,
		IncludeTransitive: in.IncludeTransitive,
		Resolve:           walk,
	}, h.Queue)
	if err != nil {
		var conflict *requests.ConflictError
		if errors.As(err, &conflict) {
			// Повтор с тем же ключом возвращает ту же заявку и код 200:
			// повторная отправка из CI — не ошибка, а нормальная жизнь.
			h.respondIdempotent(w, r, conflict.RequestID)
			return
		}
		writeError(w, r, errInternal("Не удалось создать заявку").Because(err))
		return
	}

	status := http.StatusAccepted
	if len(itemIDs) == 0 {
		// Заводить нечего — всё уже в базе или ничего не разобралось. Это не
		// «принято к обработке»: обрабатывать нечего.
		status = http.StatusOK
	}
	writeJSON(w, status, createResponse(created, parsed))
}

// readCreateInput разбирает тело: JSON или multipart.
func (h *RequestsHandler) readCreateInput(r *http.Request) (requests.Input, *Error) {
	contentType := r.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)
	if strings.HasPrefix(mediaType, "multipart/") {
		return h.readMultipart(r, params["boundary"])
	}
	return h.readJSON(r)
}

func (h *RequestsHandler) readJSON(r *http.Request) (requests.Input, *Error) {
	limit := h.uploadLimit()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return requests.Input{}, errValidation("Тело запроса не прочитано").Because(err)
	}
	if int64(len(body)) > limit {
		return requests.Input{}, &Error{Code: "limit_exceeded", Status: http.StatusRequestEntityTooLarge,
			Message: fmt.Sprintf("Тело запроса больше допустимого размера %d байт", limit)}
	}
	if len(body) == 0 {
		return requests.Input{}, errValidation(
			"Передайте JSON {manager, packages[]} либо multipart с полями manager и file")
	}

	var payload struct {
		Manager           string            `json:"manager"`
		Reason            string            `json:"reason"`
		Packages          []json.RawMessage `json:"packages"`
		IncludeTransitive bool              `json:"include_transitive"`
		ResolveDepth      int               `json:"resolve_depth"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return requests.Input{}, errValidation(
			"Тело запроса не является корректным JSON-объектом").Because(err)
	}
	manager := strings.ToLower(strings.TrimSpace(payload.Manager))
	if manager == "" {
		return requests.Input{}, errValidation("Не указан пакетный менеджер (поле manager)")
	}
	if len(payload.Packages) == 0 {
		return requests.Input{}, errValidation("Список packages пуст или имеет неверный тип")
	}

	in := requests.Input{Manager: manager,
		IncludeTransitive: payload.IncludeTransitive, ResolveDepth: payload.ResolveDepth}
	// Элемент списка бывает строкой («requests==2.31.0») и объектом
	// {name, version}: обе формы уже используются, и поддержать нужно обе.
	for _, raw := range payload.Packages {
		var asString string
		if err := json.Unmarshal(raw, &asString); err == nil {
			if strings.TrimSpace(asString) != "" {
				in.Entries = append(in.Entries, strings.TrimSpace(asString))
			}
			continue
		}
		var asObject requests.NameVersion
		if err := json.Unmarshal(raw, &asObject); err == nil {
			in.Structured = append(in.Structured, asObject)
			continue
		}
		return requests.Input{}, errValidation(
			"Элемент packages должен быть строкой или объектом {name, version}")
	}
	in.Reason = payload.Reason
	return in, nil
}

func (h *RequestsHandler) readMultipart(r *http.Request, boundary string) (requests.Input, *Error) {
	if boundary == "" {
		return requests.Input{}, errValidation("В multipart-запросе не указана граница (boundary)")
	}
	limit := h.uploadLimit()
	reader := multipart.NewReader(io.LimitReader(r.Body, limit+multipartOverhead), boundary)

	in := requests.Input{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return requests.Input{}, errValidation("multipart-запрос не разобран").Because(err)
		}
		switch part.FormName() {
		case "manager":
			value, _ := io.ReadAll(io.LimitReader(part, 1024))
			in.Manager = strings.ToLower(strings.TrimSpace(string(value)))
		case "reason":
			value, _ := io.ReadAll(io.LimitReader(part, 4096))
			in.Reason = strings.TrimSpace(string(value))
		case "include_transitive":
			value, _ := io.ReadAll(io.LimitReader(part, 16))
			in.IncludeTransitive = isTrue(string(value))
		case "resolve_depth":
			value, _ := io.ReadAll(io.LimitReader(part, 8))
			in.ResolveDepth, _ = strconv.Atoi(strings.TrimSpace(string(value)))
		case "file":
			content, err := io.ReadAll(io.LimitReader(part, limit+1))
			if err != nil {
				return requests.Input{}, errValidation("Файл не прочитан").Because(err)
			}
			if int64(len(content)) > limit {
				return requests.Input{}, &Error{Code: "limit_exceeded",
					Status:  http.StatusRequestEntityTooLarge,
					Message: fmt.Sprintf("Файл больше допустимого размера %d байт", limit)}
			}
			in.Filename = part.FileName()
			in.Content = content
		}
		_ = part.Close()
	}

	if in.Content == nil {
		return requests.Input{}, errValidation("В multipart-запросе нет файла в поле file")
	}
	if in.Manager == "" {
		return requests.Input{}, errValidation("Для загрузки файла нужно указать поле manager")
	}
	return in, nil
}

// multipartOverhead — запас на заголовки частей поверх предела на сам файл.
const multipartOverhead = 64 << 10

func (h *RequestsHandler) uploadLimit() int64 {
	if h.Cfg != nil && h.Cfg.MaxUploadSizeBytes > 0 {
		return h.Cfg.MaxUploadSizeBytes
	}
	return 5 << 20
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// createError переводит ошибку разбора в ответ API.
func createError(err error) error {
	switch {
	case errors.Is(err, requests.ErrEmpty):
		return errNotFound("В запросе не найдено ни одного пакета для модерации")
	case errors.Is(err, requests.ErrLimit):
		return &Error{Code: "limit_exceeded", Status: http.StatusRequestEntityTooLarge,
			Message: strings.TrimPrefix(err.Error(), "превышен предел: ")}
	case errors.Is(err, requests.ErrValidation):
		return errValidation(strings.TrimPrefix(err.Error(), "некорректный вход заявки: "))
	}
	var invalidFormat *registry.InvalidFormatError
	if errors.As(err, &invalidFormat) {
		return errValidation(invalidFormat.Message)
	}
	return errInternal("Не удалось разобрать список пакетов").Because(err)
}

func createResponse(request *domain.ModerationRequest, parsed requests.ParseResult) map[string]any {
	packages := make([]map[string]any, 0, len(parsed.Packages))
	accepted, skipped, invalid := 0, 0, 0
	for _, p := range parsed.Packages {
		switch p.State {
		case requests.StateNew:
			accepted++
		case requests.StateAlreadyInBase:
			skipped++
		case requests.StateInvalidFormat:
			invalid++
		}
		packages = append(packages, parsedPackageView(p))
	}
	return map[string]any{
		"request_id":              request.ID,
		"manager":                 request.Manager,
		"status":                  request.Status,
		"accepted":                accepted,
		"skipped_already_in_base": skipped,
		"invalid":                 invalid,
		"warnings":                listOrEmpty(parsed.Warnings),
		"packages":                packages,
		"status_url":              "/api/v1/requests/" + strconv.FormatInt(request.ID, 10),
	}
}

func parsedPackageView(p requests.Parsed) map[string]any {
	view := map[string]any{
		"raw":             p.Raw,
		"state":           p.State,
		"dependency_kind": valueOrDirect(p.DependencyKind),
	}
	if p.Ref != nil {
		view["name"] = p.Ref.DisplayName
		view["version"] = p.Ref.RawVersion
	}
	if p.Message != "" {
		view["message"] = p.Message
	}
	if p.ExpectedFormat != "" {
		view["expected_format"] = p.ExpectedFormat
	}
	if p.ExistingVersionID != nil {
		view["package_version_id"] = *p.ExistingVersionID
		view["link"] = "/api/v1/packages/" + strconv.FormatInt(*p.ExistingVersionID, 10)
	}
	if p.ExistingStatus != "" {
		view["status"] = p.ExistingStatus
	}
	if p.InstallCommand != "" {
		view["install_command"] = p.InstallCommand
	}
	if p.Depth > 0 {
		view["depth"] = p.Depth
		view["required_range"] = p.RequiredRange
		view["required_by"] = parentEntry(p.ParentKey)
	}
	return view
}

// respondIdempotent отдаёт уже существующую заявку: повтор с тем же ключом —
// нормальная жизнь CI, а не ошибка.
func (h *RequestsHandler) respondIdempotent(w http.ResponseWriter, r *http.Request, requestID int64) {
	request, err := h.Repo.GetModerationRequest(r.Context(), requestID)
	if err != nil || request == nil {
		writeError(w, r, errInternal("Заявка по этому Idempotency-Key не прочитана").Because(err))
		return
	}
	items, err := h.Repo.ListItemsByRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, r, errInternal("Пакеты заявки не прочитаны").Because(err))
		return
	}
	packages := make([]map[string]any, 0, len(items))
	for _, item := range items {
		packages = append(packages, map[string]any{
			"raw":             strings.TrimSpace(item.RequestedName + " " + item.RequestedVersion),
			"state":           requests.StateNew,
			"name":            item.RequestedName,
			"version":         item.RequestedVersion,
			"dependency_kind": item.DependencyKind,
			"status":          item.Status,
			"message":         "Заявка уже создана ранее с этим Idempotency-Key",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id":              request.ID,
		"manager":                 request.Manager,
		"status":                  request.Status,
		"accepted":                len(items),
		"skipped_already_in_base": 0,
		"invalid":                 0,
		"warnings":                listOrEmpty(request.Warnings),
		"packages":                packages,
		"status_url":              "/api/v1/requests/" + strconv.FormatInt(request.ID, 10),
	})
}

func valueOrDirect(kind string) string {
	if kind == "" {
		return "direct"
	}
	return kind
}

// resolveOptions — пределы раскрытия для одного запроса: настройки сервиса
// плюс глубина, которую попросил пользователь. Просить БОЛЬШЕ настроенного
// нельзя: глубина — это не удобство, а стоимость, которую платит и реестр, и
// очередь людей, разбирающих заявку.
func (h *RequestsHandler) resolveOptions(depth int) resolve.Options {
	opts := resolve.DefaultOptions()
	if h.Cfg != nil {
		opts = resolve.Options{
			MaxDepth:        h.Cfg.ResolveMaxDepth,
			MaxNodes:        h.Cfg.ResolveMaxPackages,
			IncludeOptional: h.Cfg.ResolveIncludeOptional,
			Concurrency:     h.Cfg.ResolveConcurrency,
		}
	}
	if depth > 0 && depth < opts.MaxDepth {
		opts.MaxDepth = depth
	}
	return opts
}

// parentEntry — человеческое имя родителя из ключа узла
// («pypi:urllib3:2.0.7» -> «urllib3 2.0.7»). Ключ наружу не отдаётся: он
// внутренний и в интерфейсе не значит ничего.
func parentEntry(key string) string {
	parts := strings.Split(key, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[1:len(parts)-1], ":") + " " + parts[len(parts)-1]
}
