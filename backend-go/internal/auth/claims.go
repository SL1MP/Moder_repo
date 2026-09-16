// Package auth — проверка токенов доступа и разбор ролей.
//
// Порт backend/app/core/security.py. Основной способ входа — OIDC
// (Authorization Code + PKCE) к Keycloak: SPA получает токен, сервис проверяет
// подпись по JWKS издателя. Группы каталога маппятся в роли сервиса
// переменными ROLE_MAPPING_*. Fallback-вход логин/пароль (HS256-токен нашей
// подписи) — только сервисные учётки, включается LOCAL_AUTH_ENABLED, в prod
// выключен.
//
// Проверка подписи собрана на stdlib, без библиотеки JWT. Причина та же, по
// которой в internal/storage руками написан SigV4: набор алгоритмов здесь
// закрытый (RS256/RS512/ES256 для OIDC, HS256 для локальных токенов), и
// сервис, который существует ради контроля за внешними зависимостями, не
// тянет ради этого ещё одну зависимость. Единственная внешняя библиотека в
// пакете — x/crypto/bcrypt: свою реализацию bcrypt писать нельзя.
package auth

import (
	"sort"
	"strconv"
	"strings"
)

// LocalIssuer — значение claim `iss` у токенов, выпущенных самим сервисом.
// Совпадает с константой python-версии: токен, выданный одной версией,
// обязан приниматься другой.
const LocalIssuer = "moderation-local"

// Roles — роли сервиса в порядке убывания полномочий. Порядок важен:
// PrimaryRole отдаёт первую подходящую, и по ней подписываются решения.
var Roles = []string{"admin", "devsecops", "legal", "developer"}

// RoleTitles — названия ролей для сообщений об отказе.
var RoleTitles = map[string]string{
	"admin":     "администратор",
	"devsecops": "DevSecOps",
	"legal":     "юрист",
	"developer": "разработчик",
}

// Claims — нормализованные данные токена. Порт TokenClaims.
type Claims struct {
	Subject   string
	Username  string
	Email     string
	FullName  string
	Roles     []string
	Groups    []string
	IsService bool
	// Raw — исходные claims. Нужны там, где важно не наше представление, а то,
	// что реально прислал издатель (диагностика отказов в доступе).
	Raw map[string]any
}

// PrimaryRole — старшая роль пользователя, та, от имени которой считается
// принятым решение. Порт security.primary_role.
func PrimaryRole(roles []string) string {
	for _, role := range Roles {
		for _, have := range roles {
			if have == role {
				return role
			}
		}
	}
	return ""
}

// RoleMapper — то, что умеет превращать группу каталога в роль сервиса.
// Интерфейсом, а не *config.Config: пакету auth не нужен весь конфиг, а
// тестам не нужно его собирать.
type RoleMapper interface {
	RoleForGroup(group string) string
}

// claimsFromOIDC — нормализация claims Keycloak. Порт _claims_from_oidc.
//
// Группы собираются из четырёх мест, потому что Keycloak кладёт их
// по-разному в зависимости от настройки маппера клиента: плоский claim
// groups/roles, realm_access.roles и resource_access.<client>.roles. Пропуск
// любого из них выглядит как «у пользователя нет ролей» при корректной
// настройке каталога.
func claimsFromOIDC(payload map[string]any, mapper RoleMapper) (Claims, error) {
	subject, _ := payload["sub"].(string)
	if subject == "" {
		return Claims{}, &Error{Message: "В токене нет claim sub — непонятно, чей это токен"}
	}

	var groups []string
	for _, key := range []string{"groups", "roles"} {
		for _, v := range stringList(payload[key]) {
			// Keycloak отдаёт группы с ведущим слэшем («/moderation-admin»),
			// а в ROLE_MAPPING_* они записаны без него.
			groups = append(groups, strings.TrimPrefix(v, "/"))
		}
	}
	if realm, ok := payload["realm_access"].(map[string]any); ok {
		groups = append(groups, stringList(realm["roles"])...)
	}
	if resources, ok := payload["resource_access"].(map[string]any); ok {
		for _, client := range resources {
			if m, ok := client.(map[string]any); ok {
				groups = append(groups, stringList(m["roles"])...)
			}
		}
	}

	roleSet := map[string]bool{}
	for _, g := range groups {
		if role := mapper.RoleForGroup(g); role != "" {
			roleSet[role] = true
		}
	}

	email, _ := payload["email"].(string)
	clientID, _ := payload["client_id"].(string)
	username := firstNonEmpty(
		str(payload["preferred_username"]), email, clientID, str(payload["azp"]), subject)

	return Claims{
		Subject:   subject,
		Username:  username,
		Email:     email,
		FullName:  str(payload["name"]),
		Roles:     sortedKeys(roleSet),
		Groups:    unique(groups),
		IsService: clientID != "" && email == "",
		Raw:       payload,
	}, nil
}

// claimsFromLocal — разбор токена, выпущенного самим сервисом. Роли в нём
// лежат прямо в токене: сопоставлять с группами каталога нечего.
// Порт _claims_from_local.
func claimsFromLocal(payload map[string]any) (Claims, error) {
	subject, _ := payload["sub"].(string)
	if subject == "" {
		return Claims{}, &Error{Message: "В локальном токене нет claim sub"}
	}
	return Claims{
		Subject:   subject,
		Username:  firstNonEmpty(str(payload["username"]), subject),
		Email:     str(payload["email"]),
		FullName:  str(payload["name"]),
		Roles:     stringList(payload["roles"]),
		IsService: true,
		Raw:       payload,
	}, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// stringList приводит значение claim к списку строк. Нестроковые элементы
// приводятся к строке так же, как это делает python-версия (str(v)) —
// числовая роль в каталоге не должна молча пропадать.
func stringList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch t := item.(type) {
		case string:
			out = append(out, t)
		case float64:
			out = append(out, strconv.FormatFloat(t, 'f', -1, 64))
		default:
			continue
		}
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]bool{}
	for _, v := range values {
		seen[v] = true
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
