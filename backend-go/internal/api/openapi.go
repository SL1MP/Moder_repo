package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// OpenAPI документируется рядом с роутером, а не генерируется из Python-
// аннотаций: production API полностью обслуживает Go. Спецификация строится
// из компактного списка маршрутов, чтобы Swagger, ReDoc и реальный chi-router
// использовали одинаковые пути и методы.

const swaggerHTML = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Модерация пакетов — Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css">
  <style>html{box-sizing:border-box;overflow-y:scroll}*,*:before,*:after{box-sizing:inherit}body{margin:0;background:#fafafa}</style>
</head>
<body>
  <div id="swagger-ui"><p>Загрузка Swagger UI… Если интерфейс не появился, откройте <a href="/api/openapi.json">OpenAPI JSON</a>.</p></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: '/api/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        displayRequestDuration: true,
        persistAuthorization: true,
        docExpansion: 'none',
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: 'StandaloneLayout'
      })
    }
  </script>
</body>
</html>`

const redocHTML = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Модерация пакетов — ReDoc</title>
  <style>body{margin:0;padding:0}</style>
</head>
<body>
  <redoc spec-url="/api/openapi.json" expand-responses="200,201,202"></redoc>
  <noscript>Для ReDoc требуется JavaScript. Спецификация доступна по адресу /api/openapi.json.</noscript>
  <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"></script>
</body>
</html>`

const docsCSP = "default-src 'none'; " +
	"script-src https://cdn.jsdelivr.net 'unsafe-inline'; " +
	"style-src https://cdn.jsdelivr.net 'unsafe-inline'; " +
	"img-src data: https:; font-src https://cdn.jsdelivr.net; connect-src 'self'"

// MountOpenAPI подключает те же публичные адреса, которые раньше отдавал
// FastAPI. Это важно не только для людей: /api/openapi.json используют
// генераторы клиентов и контрактные проверки.
func MountOpenAPI(r chi.Router) {
	r.Get("/api/openapi.json", serveOpenAPI)
	r.Get("/api/docs", serveDocs(swaggerHTML))
	r.Get("/api/docs/", redirectDocs("/api/docs"))
	r.Get("/api/redoc", serveDocs(redocHTML))
	r.Get("/api/redoc/", redirectDocs("/api/redoc"))
}

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	body, err := openAPIJSON()
	if err != nil {
		http.Error(w, "OpenAPI specification is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func serveDocs(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", docsCSP)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page))
	}
}

func redirectDocs(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}
}

type openAPIRoute struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Tag         string
	Public      bool
	SuccessCode string
	Roles       []string
	Query       []openAPIParam
	Body        map[string]any
	Response    map[string]any
}

type openAPIParam struct {
	Name        string
	Description string
	Required    bool
	Schema      map[string]any
}

var (
	openAPIOnce sync.Once
	openAPIBody []byte
	openAPIErr  error
)

func openAPIJSON() ([]byte, error) {
	openAPIOnce.Do(func() {
		openAPIBody, openAPIErr = json.MarshalIndent(buildOpenAPI(), "", "  ")
	})
	return openAPIBody, openAPIErr
}

func buildOpenAPI() map[string]any {
	paths := map[string]any{}
	for _, route := range openAPIRoutes() {
		item, _ := paths[route.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[route.Path] = item
		}
		item[strings.ToLower(route.Method)] = operationFor(route)
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Модерация пакетов API",
			"version":     "1.0.0",
			"description": "Go API сервиса модерации внешних пакетов, проверки и публикации во внутренний артефактори.",
		},
		"tags": []map[string]any{
			{"name": "Система", "description": "Здоровье и наблюдаемость"},
			{"name": "Аутентификация"}, {"name": "Менеджеры"}, {"name": "Пакеты"},
			{"name": "Заявки"}, {"name": "Зависимости"}, {"name": "Очереди"},
			{"name": "Решения"}, {"name": "Лицензии"}, {"name": "Обсуждения"},
			{"name": "Уведомления"}, {"name": "Отчёты"}, {"name": "SBOM"},
			{"name": "GitLab"}, {"name": "Администрирование"},
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
					"description": "OIDC JWT или токен локальной сервисной учётки",
				},
			},
			"schemas": openAPISchemas(),
		},
	}
}

func operationFor(route openAPIRoute) map[string]any {
	code := route.SuccessCode
	if code == "" {
		code = "200"
	}
	response := route.Response
	if response == nil {
		response = jsonResponseSchema(map[string]any{"type": "object", "additionalProperties": true})
	}
	op := map[string]any{
		"operationId": route.OperationID,
		"summary":     route.Summary,
		"tags":        []string{route.Tag},
		"responses": map[string]any{
			code: map[string]any{"description": successDescription(code), "content": response},
			"default": map[string]any{
				"description": "Ошибка",
				"content": jsonResponseSchema(refSchema("ErrorEnvelope")),
			},
		},
	}
	if route.Public {
		op["security"] = []any{}
	} else {
		op["security"] = []any{map[string]any{"bearerAuth": []string{}}}
	}
	if len(route.Roles) > 0 {
		op["x-required-roles"] = route.Roles
		op["description"] = "Требуемые роли: " + strings.Join(route.Roles, ", ") + "."
	}
	params := pathParameters(route.Path)
	for _, query := range route.Query {
		params = append(params, map[string]any{
			"name": query.Name, "in": "query", "required": query.Required,
			"description": query.Description, "schema": query.Schema,
		})
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	if route.Body != nil {
		op["requestBody"] = route.Body
	}
	return op
}

var pathParameterRE = regexp.MustCompile(`\{([^}]+)\}`)

func pathParameters(path string) []map[string]any {
	matches := pathParameterRE.FindAllStringSubmatch(path, -1)
	params := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		schema := map[string]any{"type": "integer", "format": "int64", "minimum": 1}
		if match[1] == "file" {
			schema = map[string]any{"type": "string"}
		}
		params = append(params, map[string]any{
			"name": match[1], "in": "path", "required": true,
			"schema": schema,
		})
	}
	return params
}

func successDescription(code string) string {
	switch code {
	case "201":
		return "Создано"
	case "202":
		return "Принято в обработку"
	case "204":
		return "Выполнено, тело отсутствует"
	default:
		return "Успешный ответ"
	}
}

func jsonResponseSchema(schema map[string]any) map[string]any {
	return map[string]any{"application/json": map[string]any{"schema": schema}}
}

func refSchema(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func jsonBody(schema map[string]any, description string) map[string]any {
	return map[string]any{
		"required": true, "description": description,
		"content": map[string]any{"application/json": map[string]any{"schema": schema}},
	}
}

func optionalJSONBody(schema map[string]any, description string) map[string]any {
	return map[string]any{
		"required": false, "description": description,
		"content": map[string]any{"application/json": map[string]any{"schema": schema}},
	}
}

func genericJSONBody(description string) map[string]any {
	return jsonBody(map[string]any{"type": "object", "additionalProperties": true}, description)
}

func integerQuery(name, description string) openAPIParam {
	return openAPIParam{Name: name, Description: description,
		Schema: map[string]any{"type": "integer", "minimum": 0}}
}

func stringQuery(name, description string) openAPIParam {
	return openAPIParam{Name: name, Description: description, Schema: map[string]any{"type": "string"}}
}

func boolQuery(name, description string) openAPIParam {
	return openAPIParam{Name: name, Description: description, Schema: map[string]any{"type": "boolean"}}
}

func openAPIRoutes() []openAPIRoute {
	loginBody := jsonBody(refSchema("LoginRequest"), "Локальный вход сервисной учётки")
	createRequestBody := map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{"schema": refSchema("CreateRequest")},
			"multipart/form-data": map[string]any{"schema": map[string]any{
				"type": "object", "required": []string{"manager", "file"},
				"properties": map[string]any{
					"manager": map[string]any{"type": "string"},
					"file": map[string]any{"type": "string", "format": "binary"},
					"reason": map[string]any{"type": "string"},
					"include_transitive": map[string]any{"type": "boolean", "default": false},
					"resolve_depth": map[string]any{"type": "integer", "minimum": 1},
				},
			}},
		},
	}
	decisionBody := jsonBody(refSchema("DecisionRequest"), "Решение ответственной роли")
	commentBody := jsonBody(refSchema("CommentRequest"), "Комментарий к заявке")

	return []openAPIRoute{
		{Method: "GET", Path: "/health", OperationID: "health", Summary: "Проверить процесс API", Tag: "Система", Public: true, Response: map[string]any{"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}},
		{Method: "GET", Path: "/health/db", OperationID: "healthDatabase", Summary: "Проверить подключение к PostgreSQL", Tag: "Система", Public: true, Response: map[string]any{"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}},
		{Method: "GET", Path: "/metrics", OperationID: "metrics", Summary: "Получить метрики Prometheus", Tag: "Система", Public: true, Response: map[string]any{"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}},

		{Method: "GET", Path: "/api/v1/auth/config", OperationID: "getAuthConfig", Summary: "Получить настройки входа", Tag: "Аутентификация", Public: true},
		{Method: "POST", Path: "/api/v1/auth/token", OperationID: "createLocalToken", Summary: "Войти локальной сервисной учёткой", Tag: "Аутентификация", Public: true, Body: loginBody, Response: jsonResponseSchema(refSchema("TokenResponse"))},
		{Method: "GET", Path: "/api/v1/auth/me", OperationID: "getCurrentUser", Summary: "Получить текущего пользователя", Tag: "Аутентификация"},

		{Method: "GET", Path: "/api/v1/managers", OperationID: "listManagers", Summary: "Получить пакетные менеджеры", Tag: "Менеджеры"},
		{Method: "GET", Path: "/api/v1/managers/detect", OperationID: "detectManager", Summary: "Определить менеджер по имени файла", Tag: "Менеджеры", Query: []openAPIParam{{Name: "filename", Description: "Имя файла зависимостей", Required: true, Schema: map[string]any{"type": "string"}}}},

		{Method: "GET", Path: "/api/v1/packages", OperationID: "searchPackages", Summary: "Искать пакеты в базе", Tag: "Пакеты", Query: []openAPIParam{stringQuery("q", "Поиск по имени"), stringQuery("manager", "Код менеджера"), stringQuery("version", "Версия"), stringQuery("status", "Статус"), integerQuery("limit", "Размер страницы, максимум 200"), integerQuery("offset", "Смещение")}},
		{Method: "GET", Path: "/api/v1/packages/{versionID}", OperationID: "getPackageVersion", Summary: "Получить версию пакета", Tag: "Пакеты"},
		{Method: "POST", Path: "/api/v1/packages/check", OperationID: "checkPackages", Summary: "Проверить наличие и возможность установки", Tag: "Пакеты", Body: genericJSONBody("Менеджер и список пакетов")},
		{Method: "POST", Path: "/api/v1/packages/{versionID}/revoke", OperationID: "revokePackageVersion", Summary: "Отозвать ранее одобренную версию", Tag: "Пакеты", Roles: []string{"admin", "devsecops"}, Body: genericJSONBody("Причина отзыва")},

		{Method: "GET", Path: "/api/v1/requests", OperationID: "listRequests", Summary: "Получить заявки", Tag: "Заявки", Query: []openAPIParam{stringQuery("status", "Статус заявки"), stringQuery("manager", "Код менеджера"), boolQuery("mine", "Только свои заявки"), integerQuery("limit", "Размер страницы, максимум 200"), integerQuery("offset", "Смещение")}},
		{Method: "POST", Path: "/api/v1/requests", OperationID: "createRequest", Summary: "Создать заявку на модерацию", Tag: "Заявки", SuccessCode: "202", Body: createRequestBody},
		{Method: "GET", Path: "/api/v1/requests/{requestID}", OperationID: "getRequest", Summary: "Получить карточку заявки", Tag: "Заявки"},
		{Method: "POST", Path: "/api/v1/requests/{requestID}/retry", OperationID: "retryRequest", Summary: "Перезапустить все упавшие пакеты заявки", Tag: "Заявки"},
		{Method: "POST", Path: "/api/v1/requests/{requestID}/items/{itemID}/retry", OperationID: "retryRequestItem", Summary: "Перезапустить пакет с выбранного шага", Tag: "Заявки", Body: optionalJSONBody(refSchema("RetryItemRequest"), "Код шага, с которого повторить проверку; без тела проверка начнётся с первого шага")},
		{Method: "POST", Path: "/api/v1/requests/{requestID}/cancel", OperationID: "cancelRequest", Summary: "Закрыть свою заявку", Tag: "Заявки", Body: genericJSONBody("Необязательная причина закрытия")},
		{Method: "POST", Path: "/api/v1/dependencies/resolve", OperationID: "resolveDependencies", Summary: "Предварительно раскрыть дерево зависимостей", Tag: "Зависимости", Body: genericJSONBody("Менеджер, пакеты и глубина")},

		{Method: "GET", Path: "/api/v1/queue/security", OperationID: "getSecurityQueue", Summary: "Получить очередь DevSecOps", Tag: "Очереди", Roles: []string{"devsecops"}},
		{Method: "GET", Path: "/api/v1/queue/legal", OperationID: "getLegalQueue", Summary: "Получить очередь юристов", Tag: "Очереди", Roles: []string{"legal"}},
		{Method: "GET", Path: "/api/v1/queue/counters", OperationID: "getQueueCounters", Summary: "Получить счётчики очередей", Tag: "Очереди"},

		{Method: "POST", Path: "/api/v1/items/{itemID}/quarantine/release", OperationID: "releaseQuarantine", Summary: "Досрочно снять карантин", Tag: "Решения", Roles: []string{"devsecops"}, Body: genericJSONBody("Комментарий")},
		{Method: "POST", Path: "/api/v1/items/{itemID}/security-decision", OperationID: "makeSecurityDecision", Summary: "Принять решение DevSecOps", Tag: "Решения", Roles: []string{"devsecops"}, Body: decisionBody},
		{Method: "POST", Path: "/api/v1/items/{itemID}/license-claim", OperationID: "claimLicense", Summary: "Заявить лицензию пакета", Tag: "Лицензии", Body: genericJSONBody("URL, SPDX и комментарий")},
		{Method: "GET", Path: "/api/v1/license-claims", OperationID: "listLicenseClaims", Summary: "Получить заявления о лицензиях", Tag: "Лицензии", Query: []openAPIParam{stringQuery("status", "Статус заявления")}},
		{Method: "GET", Path: "/api/v1/license-claims/{claimID}", OperationID: "getLicenseClaim", Summary: "Получить заявление о лицензии", Tag: "Лицензии"},
		{Method: "POST", Path: "/api/v1/license-claims/{claimID}/decision", OperationID: "makeLicenseDecision", Summary: "Принять решение юриста", Tag: "Лицензии", Roles: []string{"legal"}, Body: decisionBody},
		{Method: "GET", Path: "/api/v1/licenses", OperationID: "listLicenses", Summary: "Получить справочник лицензий", Tag: "Лицензии"},

		{Method: "GET", Path: "/api/v1/requests/{requestID}/comments", OperationID: "listComments", Summary: "Получить обсуждение заявки", Tag: "Обсуждения", Query: []openAPIParam{integerQuery("request_item_id", "Фильтр по пакету заявки")}},
		{Method: "POST", Path: "/api/v1/requests/{requestID}/comments", OperationID: "createComment", Summary: "Добавить комментарий", Tag: "Обсуждения", Body: commentBody},
		{Method: "PATCH", Path: "/api/v1/comments/{commentID}", OperationID: "updateComment", Summary: "Изменить свой комментарий", Tag: "Обсуждения", Body: commentBody},
		{Method: "DELETE", Path: "/api/v1/comments/{commentID}", OperationID: "deleteComment", Summary: "Удалить свой комментарий", Tag: "Обсуждения"},

		{Method: "GET", Path: "/api/v1/notifications", OperationID: "listNotifications", Summary: "Получить уведомления", Tag: "Уведомления", Query: []openAPIParam{boolQuery("only_unread", "Только непрочитанные"), integerQuery("limit", "Размер страницы, максимум 200")}},
		{Method: "POST", Path: "/api/v1/notifications/read", OperationID: "markNotificationsRead", Summary: "Отметить уведомления прочитанными", Tag: "Уведомления", Body: genericJSONBody("Массив ids либо all=true")},

		{Method: "GET", Path: "/api/v1/request-items/{itemID}/reports", OperationID: "listScanReports", Summary: "Получить отчёты сканирования", Tag: "Отчёты"},
		{Method: "GET", Path: "/api/v1/request-items/{itemID}/reports/{file}", OperationID: "downloadScanReport", Summary: "Открыть HTML или JSON отчёт", Tag: "Отчёты", Response: map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}, "text/html": map[string]any{"schema": map[string]any{"type": "string"}}}},
		{Method: "GET", Path: "/api/v1/request-items/{itemID}/sboms", OperationID: "listSBOMs", Summary: "Получить список CycloneDX SBOM", Tag: "SBOM"},
		{Method: "GET", Path: "/api/v1/request-items/{itemID}/sboms/{file}", OperationID: "downloadSBOM", Summary: "Скачать CycloneDX JSON", Tag: "SBOM"},

		{Method: "GET", Path: "/api/v1/gitlab/status", OperationID: "getGitLabStatus", Summary: "Получить состояние подключения GitLab", Tag: "GitLab"},
		{Method: "GET", Path: "/api/v1/gitlab/authorize", OperationID: "authorizeGitLab", Summary: "Начать OAuth-подключение GitLab", Tag: "GitLab"},
		{Method: "GET", Path: "/api/v1/gitlab/callback", OperationID: "gitLabCallback", Summary: "Завершить OAuth-подключение GitLab", Tag: "GitLab", Query: []openAPIParam{{Name: "code", Description: "OAuth code", Required: true, Schema: map[string]any{"type": "string"}}, {Name: "state", Description: "OAuth state", Required: true, Schema: map[string]any{"type": "string"}}}},
		{Method: "DELETE", Path: "/api/v1/gitlab/connection", OperationID: "disconnectGitLab", Summary: "Отключить GitLab", Tag: "GitLab"},
		{Method: "POST", Path: "/api/v1/gitlab/requests", OperationID: "createRequestFromGitLab", Summary: "Создать заявку из файла GitLab", Tag: "GitLab", SuccessCode: "202", Body: genericJSONBody("Проект, путь, ref и параметры раскрытия")},

		{Method: "GET", Path: "/api/v1/settings", OperationID: "getSettings", Summary: "Получить действующие настройки", Tag: "Администрирование"},
		{Method: "PUT", Path: "/api/v1/settings", OperationID: "updateSettings", Summary: "Сохранить web-настройки", Tag: "Администрирование", Roles: []string{"admin"}, Body: genericJSONBody("Карта values: имя настройки → значение")},
		{Method: "GET", Path: "/api/v1/settings/policies", OperationID: "getPolicyState", Summary: "Получить состояние политик", Tag: "Администрирование"},
		{Method: "GET", Path: "/api/v1/system/status", OperationID: "getSystemStatus", Summary: "Получить состояние компонентов", Tag: "Администрирование"},
		{Method: "GET", Path: "/api/v1/admin/users", OperationID: "listUsers", Summary: "Получить пользователей и роли приложения", Tag: "Администрирование", Roles: []string{"admin"}},
		{Method: "POST", Path: "/api/v1/admin/users", OperationID: "createUser", Summary: "Заранее создать OIDC-пользователя", Tag: "Администрирование", Roles: []string{"admin"}, Body: genericJSONBody("Логин, профиль и роли")},
		{Method: "PATCH", Path: "/api/v1/admin/users/{userID}", OperationID: "updateUserAccess", Summary: "Изменить роли и активность пользователя", Tag: "Администрирование", Roles: []string{"admin"}, Body: genericJSONBody("Роли и активность")},
		{Method: "POST", Path: "/api/v1/admin/reload", OperationID: "reloadPolicies", Summary: "Перезагрузить политики", Tag: "Администрирование", Roles: []string{"admin"}},
		{Method: "GET", Path: "/api/v1/admin/audit", OperationID: "getAuditLog", Summary: "Получить аудит", Tag: "Администрирование", Roles: []string{"admin"}, Query: []openAPIParam{stringQuery("entity_type", "Тип сущности"), stringQuery("entity_id", "ID сущности"), stringQuery("action", "Действие"), stringQuery("actor", "Исполнитель"), integerQuery("limit", "Размер страницы"), integerQuery("offset", "Смещение")}},
		{Method: "POST", Path: "/api/v1/admin/queue-sweep", OperationID: "sweepQueue", Summary: "Запустить сторож очереди", Tag: "Администрирование", Roles: []string{"admin"}},
		{Method: "GET", Path: "/api/v1/admin/osv-versions", OperationID: "listOSVVersions", Summary: "Получить версии снапшота OSV", Tag: "Администрирование", Roles: []string{"devsecops"}},
		{Method: "POST", Path: "/api/v1/admin/osv-sync", OperationID: "syncOSV", Summary: "Синхронизировать снапшот OSV", Tag: "Администрирование", Roles: []string{"devsecops"}, Query: []openAPIParam{boolQuery("force", "Принудительно скачать заново")}},
	}
}

func openAPISchemas() map[string]any {
	return map[string]any{
		"ErrorEnvelope": map[string]any{
			"type": "object", "required": []string{"error"},
			"properties": map[string]any{"error": refSchema("APIError")},
		},
		"APIError": map[string]any{
			"type": "object", "required": []string{"code", "message", "request_id"},
			"properties": map[string]any{
				"code": map[string]any{"type": "string", "example": "validation_error"},
				"message": map[string]any{"type": "string"},
				"details": map[string]any{"type": "object", "additionalProperties": true, "nullable": true},
				"request_id": map[string]any{"type": "string"},
			},
		},
		"LoginRequest": map[string]any{
			"type": "object", "required": []string{"username", "password"},
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string", "format": "password"},
			},
		},
		"TokenResponse": map[string]any{
			"type": "object", "required": []string{"access_token", "token_type"},
			"properties": map[string]any{
				"access_token": map[string]any{"type": "string"},
				"token_type": map[string]any{"type": "string", "example": "bearer"},
				"expires_in": map[string]any{"type": "integer"},
				"roles": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
		},
		"PackageInput": map[string]any{
			"type": "object", "required": []string{"name", "version"},
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
				"version": map[string]any{"type": "string"},
			},
		},
		"CreateRequest": map[string]any{
			"type": "object", "required": []string{"manager", "packages"},
			"properties": map[string]any{
				"manager": map[string]any{"type": "string", "example": "pypi"},
				"packages": map[string]any{
					"type": "array", "items": map[string]any{
						"oneOf": []any{map[string]any{"type": "string"}, refSchema("PackageInput")},
					},
				},
				"reason": map[string]any{"type": "string"},
				"include_transitive": map[string]any{"type": "boolean", "default": false},
				"resolve_depth": map[string]any{"type": "integer", "minimum": 1},
			},
		},
		"DecisionRequest": map[string]any{
			"type": "object", "required": []string{"approve"},
			"properties": map[string]any{
				"approve": map[string]any{"type": "boolean"},
				"comment": map[string]any{"type": "string", "maxLength": 4000},
			},
		},
		"CommentRequest": map[string]any{
			"type": "object", "required": []string{"body"},
			"properties": map[string]any{
				"body": map[string]any{"type": "string"},
				"request_item_id": map[string]any{"type": "integer", "format": "int64", "nullable": true},
			},
		},
		"RetryItemRequest": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"from_step": map[string]any{
					"type": "string", "default": "db_check",
					"enum": []string{"db_check", "blacklist", "quarantine", "license", "download", "vuln_scan", "sandbox_scan", "sbom", "publish"},
				},
			},
		},
	}
}
