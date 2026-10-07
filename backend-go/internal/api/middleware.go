package api

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"moderation/internal/auth"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Аутентификация и проверка прав. Порт backend/app/api/deps.py.
//
// Права проверяются здесь, в API, а не только в интерфейсе: UI прячет
// кнопку, но ничего не мешает позвать тот же маршрут курлом.

// UserStore — то, что проверке доступа нужно от базы. Интерфейсом, а не
// *repo.Repo: так маршруты доступа проверяются без поднятого Postgres, а
// список того, что аутентификация вообще пишет в базу, виден целиком.
// Реализуется *repo.Repo.
type UserStore interface {
	SyncUser(ctx context.Context, claims repo.UserClaims, now time.Time) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	TouchLastLogin(ctx context.Context, userID int64, now time.Time) error
	InsertAuditLog(ctx context.Context, entry domain.AuditLog) error
}

// Auth — зависимости проверки доступа.
type Auth struct {
	Verifier *auth.Verifier
	Repo     UserStore
	// SessionRepo хранит refresh/PAT/OIDC-состояние Oakshield. Отдельное поле
	// сохраняет лёгкие UserStore-моки старых unit-тестов.
	SessionRepo *repo.Repo
	RefreshTTL  time.Duration
	// RuntimeOIDC читает issuer из DB-backed web-настройки и кэширует JWKS.
	// Нужен для Bearer JWT внешнего провайдера; браузерный callback использует
	// тот же экземпляр.
	RuntimeOIDC *RuntimeOIDCVerifier
	Now         func() time.Time
	// RateLimit — ограничение частоты запросов, применяется ПОСЛЕ опознания
	// пользователя: считаем по нему, а не по адресу (см. ratelimit.go).
	//
	// Здесь, а не отдельным r.Use в роутере, потому что каждый маршрут
	// закрывается своим Authenticate: отдельное подключение пришлось бы
	// повторять в каждом Mount*, и первый же забытый вызов оставил бы
	// маршрут без лимита незаметно.
	RateLimit func(http.Handler) http.Handler
}

var _ UserStore = (*repo.Repo)(nil)

func (a *Auth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

type userKey struct{}

// CurrentUser — пользователь текущего запроса. Второе значение false, если
// маршрут не закрыт Authenticate: тогда это ошибка сборки роутера, а не
// отсутствие прав, и обработчик обязан её заметить.
func CurrentUser(ctx context.Context) (*domain.User, bool) {
	user, ok := ctx.Value(userKey{}).(*domain.User)
	return user, ok
}

// Authenticate проверяет внутренний access JWT, PAT или внешний OIDC Bearer-
// токен и заводит/обновляет OIDC-учётку при первом обращении.
//
// Профиль синхронизируется на каждом запросе, но роли обычных пользователей
// принадлежат приложению и не перезаписываются claims из Keycloak. Роли из
// токена остаются авторитетными только для сервисных учёток.
func (a *Auth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			writeError(w, r, errUnauthorized("Не передан Bearer-токен в заголовке Authorization"))
			return
		}
		token := strings.TrimSpace(header[len("bearer "):])
		if strings.HasPrefix(token, auth.APITokenPrefix) && a.SessionRepo != nil {
			user, apiToken, err := a.SessionRepo.UserByAPITokenHash(r.Context(), auth.HashToken(token))
			if err != nil || user == nil || apiToken == nil || !user.IsActive ||
				(apiToken.ExpiresAt != nil && a.now().After(*apiToken.ExpiresAt)) {
				writeError(w, r, errUnauthorized("Недействительный персональный API-токен"))
				return
			}
			_ = a.SessionRepo.TouchAPIToken(r.Context(), apiToken.ID)
			a.serveUser(w, r, next, user)
			return
		}

		issuer, _ := auth.PeekIssuer(token)
		var claims auth.Claims
		var err error
		if issuer != "" && issuer != auth.LocalIssuer && a.RuntimeOIDC != nil {
			claims, err = a.RuntimeOIDC.Decode(r.Context(), token)
		} else {
			claims, err = a.Verifier.Decode(r.Context(), token)
		}
		if err != nil {
			// Сообщение проверяльщика уходит клиенту как есть: оно объясняет
			// причину отказа («истёк», «издатель не тот»), и без него
			// разбирательство упирается в безликое «401».
			writeError(w, r, errUnauthorized(err.Error()).Because(err))
			return
		}
		var user *domain.User
		if claims.Raw["iss"] != auth.LocalIssuer {
			// OakShield разрешает bearer-токен доверенного OIDC-провайдера и
			// при первом обращении создаёт пользователя по неизменяемому sub.
			// Роли из claims намеренно не передаются: права принадлежат сервису.
			user, err = a.Repo.SyncUser(r.Context(), repo.UserClaims{
				Subject: claims.Subject, Username: claims.Username,
				Email: claims.Email, FullName: claims.FullName,
			}, a.now())
		} else if a.SessionRepo != nil {
			userID, parseErr := strconv.ParseInt(claims.Subject, 10, 64)
			if parseErr != nil {
				writeError(w, r, errUnauthorized("Внутренний токен содержит неверный идентификатор пользователя"))
				return
			}
			user, err = a.SessionRepo.GetUserByID(r.Context(), userID)
		} else {
			// Совместимость лёгких моков и токенов переходного периода.
			user, err = a.Repo.GetUserByUsername(r.Context(), claims.Username)
		}
		if err != nil {
			writeError(w, r, errInternal("Не удалось прочитать учётную запись").Because(err))
			return
		}
		if user == nil {
			writeError(w, r, errUnauthorized("Пользователь токена не найден"))
			return
		}
		a.serveUser(w, r, next, user)
	})
}

func (a *Auth) serveUser(w http.ResponseWriter, r *http.Request, next http.Handler, user *domain.User) {
	if !user.IsActive {
		writeError(w, r, errForbidden("Учётная запись «"+user.Username+"» отключена"))
		return
	}
	authed := r.WithContext(context.WithValue(r.Context(), userKey{}, user))
	if a.RateLimit != nil {
		a.RateLimit(next).ServeHTTP(w, authed)
		return
	}
	next.ServeHTTP(w, authed)
}

// RequireRoles — доступ только перечисленным ролям. admin имеет доступ ко
// всему. Порт deps.require_roles.
func RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := CurrentUser(r.Context())
			if !ok {
				writeError(w, r, errInternal("Маршрут требует роли, но не закрыт проверкой токена"))
				return
			}
			if user.HasRole("admin") || user.HasRole(roles...) {
				next.ServeHTTP(w, r)
				return
			}
			titles := make([]string, 0, len(roles))
			for _, role := range roles {
				if title, ok := auth.RoleTitles[role]; ok {
					titles = append(titles, title)
				} else {
					titles = append(titles, role)
				}
			}
			writeError(w, r, errForbidden("Действие доступно ролям: "+strings.Join(titles, ", ")))
		})
	}
}

// RequireAnyRole — нужна хотя бы одна роль сервиса. Добавлять пакеты может
// любая роль, но учётка вообще без ролей — это чаще всего не «нет прав», а
// неназначенный доступ, и сообщение обязано на это указывать.
// Порт deps.require_any_role.
func RequireAnyRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := CurrentUser(r.Context())
		if !ok {
			writeError(w, r, errInternal("Маршрут требует роль, но не закрыт проверкой токена"))
			return
		}
		if len(user.Roles) == 0 {
			writeError(w, r, errForbidden(
				"У учётной записи нет ни одной роли сервиса. Обратитесь к администратору: "+
					"роль назначается на экране «Настройка → Пользователи и роли»"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP — адрес клиента для аудита. Порт deps.client_ip: за nginx реальный
// адрес приходит в X-Forwarded-For, и без него в журнале будет адрес прокси.
func ClientIP(r *http.Request) *string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if ip != "" {
			return &ip
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return &realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return nil
	}
	return &host
}
