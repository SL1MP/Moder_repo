package auth

import (
	"context"
	"time"

	"moderation/internal/config"
)

// Settings — то, что нужно проверяльщику токенов. Отдельная структура, а не
// *config.Config целиком: так пакет проверяется тестами без сборки всего
// конфига, а список того, от чего зависит доступ, виден целиком в одном месте.
type Settings struct {
	// Issuer — адрес, по которому СЕРВИС ходит за JWKS (внутренний).
	Issuer string
	// AcceptedIssuers — какие значения claim `iss` принимаем (внутренний и
	// внешний адреса одного и того же realm'а).
	AcceptedIssuers []string
	// Mapper превращает группу каталога в роль сервиса.
	Mapper RoleMapper

	LocalAuthEnabled bool
	LocalAuthSecret  string
	LocalTokenTTL    time.Duration
}

// SettingsFromConfig — настройки доступа из конфигурации сервиса.
func SettingsFromConfig(cfg *config.Config) Settings {
	return Settings{
		Issuer:           cfg.OIDCIssuer,
		AcceptedIssuers:  cfg.AcceptedIssuers(),
		Mapper:           cfg,
		LocalAuthEnabled: cfg.LocalAuthEnabled,
		LocalAuthSecret:  cfg.LocalAuthSecret,
		LocalTokenTTL:    cfg.LocalAuthTokenTTL,
	}
}

// Verifier проверяет токены доступа. Потокобезопасен: один экземпляр на
// сервис, кэш JWKS общий.
type Verifier struct {
	settings Settings
	jwks     *jwksCache
	now      func() time.Time
}

// NewVerifier собирает проверяльщик. client=nil — обычный http.Client;
// подменяется в тестах. now=nil — time.Now.
func NewVerifier(settings Settings, client Doer, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		settings: settings,
		jwks:     newJWKSCache(settings.Issuer, client, now),
		now:      now,
	}
}

// Decode проверяет подпись и срок действия токена и возвращает
// нормализованные claims. Порт security.decode_token.
//
// Способ проверки выбирается по claim `iss` ДО проверки подписи — иначе
// непонятно, чьим ключом проверять. Подделать этим ничего нельзя: локальный
// issuer ведёт к проверке нашим секретом, любой другой — к проверке ключом
// Keycloak, и подписать токен подделыватель не может ни в том, ни в другом
// случае. Заодно локальный путь закрыт флагом LOCAL_AUTH_ENABLED.
func (v *Verifier) Decode(ctx context.Context, token string) (Claims, error) {
	parsed, err := parseJWT(token)
	if err != nil {
		return Claims{}, err
	}

	if parsed.issuer == LocalIssuer {
		if !v.settings.LocalAuthEnabled {
			return Claims{}, &Error{Message: "Локальная аутентификация отключена (LOCAL_AUTH_ENABLED=false)"}
		}
		if err := parsed.verifySignature([]byte(v.settings.LocalAuthSecret), []string{algHS256}); err != nil {
			return Claims{}, err
		}
		if err := parsed.verifyClaims(v.now(), []string{LocalIssuer}); err != nil {
			return Claims{}, err
		}
		return claimsFromLocal(parsed.payload)
	}

	key, err := v.jwks.key(ctx, parsed.kid)
	if err != nil {
		return Claims{}, err
	}
	if err := parsed.verifySignature(key, []string{algRS256, algRS512, algES256}); err != nil {
		return Claims{}, err
	}
	if err := parsed.verifyClaims(v.now(), v.settings.AcceptedIssuers); err != nil {
		return Claims{}, err
	}
	return claimsFromOIDC(parsed.payload, v.settings.Mapper)
}
