package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"moderation/internal/domain"
)

// bcryptMaxBytes — bcrypt учитывает только первые 72 байта пароля (столько
// съедает развёртка ключа Blowfish), и python-версия обрезает пароль явно,
// по БАЙТАМ (BCRYPT_MAX_BYTES). Здесь обрезка обязана быть такой же, причём
// ради HashPassword: x/crypto/bcrypt.GenerateFromPassword на пароле длиннее
// 72 байт возвращает ошибку, тогда как python-версия такой пароль спокойно
// принимает — без обрезки учётку с длинным паролем стало бы невозможно
// завести. При проверке обрезка ни на что не влияет (лишний хвост Blowfish
// и так не видит), но делается явно, чтобы обе стороны считали одно и то же.
const bcryptMaxBytes = 72

// IssueLocalToken выпускает HS256-токен локальной или сервисной учётки.
// Возвращает токен и срок жизни в секундах. Порт security.issue_local_token.
func (v *Verifier) IssueLocalToken(user *domain.User) (string, int, error) {
	ttl := int(v.settings.LocalTokenTTL / time.Second)
	now := v.now()
	payload := map[string]any{
		"iss":          LocalIssuer,
		"sub":          fmt.Sprintf("%d", user.ID),
		"username":     user.Username,
		"email":        stringOrNil(user.Email),
		"name":         stringOrNil(user.FullName),
		"roles":        rolesOrEmpty(user.Roles),
		"is_service":   user.IsService,
		"is_superuser": user.IsSuperuser,
		"source":       user.Source,
		"iat":          now.Unix(),
		"exp":          now.Add(v.settings.LocalTokenTTL).Unix(),
	}
	token, err := signHS256(payload, []byte(v.settings.LocalAuthSecret))
	if err != nil {
		return "", 0, err
	}
	return token, ttl, nil
}

func signHS256(payload map[string]any, secret []byte) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": algHS256, "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("сборка заголовка токена: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("сборка тела токена: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyPassword — проверка пароля сервисной учётки против bcrypt-хеша,
// записанного python-версией. Пустой хеш означает «вход по паролю для этой
// учётки не настроен», а не «подойдёт любой пароль».
func VerifyPassword(password string, hash *string) bool {
	if hash == nil || *hash == "" {
		return false
	}
	if strings.HasPrefix(*hash, "$argon2id$") {
		return verifyArgon2id(password, *hash)
	}
	// Совместимость с пользователями, созданными до перехода на Argon2id.
	// Новый пароль всегда записывается Argon2id; после следующей смены bcrypt
	// исчезнет естественным образом.
	return bcrypt.CompareHashAndPassword([]byte(*hash), passwordBytes(password)) == nil
}

// Параметры соответствуют базовым рекомендациям OWASP.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword записывает PHC-строку Argon2id.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt пароля: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyArgon2id(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func passwordBytes(password string) []byte {
	b := []byte(password)
	if len(b) > bcryptMaxBytes {
		return b[:bcryptMaxBytes]
	}
	return b
}

func stringOrNil(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func rolesOrEmpty(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}
