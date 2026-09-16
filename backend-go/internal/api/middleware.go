package api

import (
	"context"
	"net/http"
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
	Now      func() time.Time
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

// Authenticate проверяет Bearer-токен и заводит/обновляет учётку.
//
// Синхронизация учётки на каждом запросе — поведение python-версии: роли
// живут в каталоге, а не у нас, и пользователь, которому только что выдали
// группу, должен получить права без похода к администратору сервиса.
func (a *Auth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			writeError(w, r, errUnauthorized("Не передан Bearer-токен в заголовке Authorization"))
			return
		}
		token := strings.TrimSpace(header[len("bearer "):])

		claims, err := a.Verifier.Decode(r.Context(), token)
		if err != nil {
			// Сообщение проверяльщика уходит клиенту как есть: оно объясняет
			// причину отказа («истёк», «издатель не тот»), и без него
			// разбирательство упирается в безликое «401».
			writeError(w, r, errUnauthorized(err.Error()).Because(err))
			return
		}

		user, err := a.Repo.SyncUser(r.Context(), repo.UserClaims{
			Subject:   claims.Subject,
			Username:  claims.Username,
			Email:     claims.Email,
			FullName:  claims.FullName,
			Roles:     claims.Roles,
			IsService: claims.IsService,
		}, a.now())
		if err != nil {
			writeError(w, r, errInternal("Не удалось синхронизировать учётную запись").Because(err))
			return
		}
		if !user.IsActive {
			writeError(w, r, errForbidden("Учётная запись «"+user.Username+"» отключена"))
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
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
// незаданный маппинг групп, и сообщение обязано на это указывать.
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
				"У учётной записи нет ни одной роли сервиса. Проверьте членство в группах каталога "+
					"и переменные ROLE_MAPPING_*"))
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
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.HasSuffix(host, "]") {
		host = host[:idx]
	}
	if host == "" {
		return nil
	}
	return &host
}
