package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

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

// IssueLocalToken выпускает HS256-токен сервисной учётки. Возвращает токен и
// срок жизни в секундах. Порт security.issue_local_token.
func (v *Verifier) IssueLocalToken(user *domain.User) (string, int, error) {
	if !v.settings.LocalAuthEnabled {
		return "", 0, &Error{Message: "Локальная аутентификация отключена (LOCAL_AUTH_ENABLED=false)"}
	}
	ttl := int(v.settings.LocalTokenTTL / time.Second)
	now := v.now()
	payload := map[string]any{
		"iss":      LocalIssuer,
		"sub":      "local:" + user.Username,
		"username": user.Username,
		"email":    stringOrNil(user.Email),
		"name":     stringOrNil(user.FullName),
		"roles":    rolesOrEmpty(user.Roles),
		"iat":      now.Unix(),
		"exp":      now.Add(v.settings.LocalTokenTTL).Unix(),
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
	return bcrypt.CompareHashAndPassword([]byte(*hash), passwordBytes(password)) == nil
}

// HashPassword — хеш пароля в том же формате, что пишет python-версия.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(passwordBytes(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("хеширование пароля: %w", err)
	}
	return string(hash), nil
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
