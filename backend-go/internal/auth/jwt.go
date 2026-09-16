package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Error — отказ в доступе с человеческим объяснением. Отдельный тип, чтобы
// API отличал «токен не прошёл» (401) от внутренней ошибки (500): неверный
// токен — штатная ситуация, и 500 на него сбивает с толку и клиента, и того,
// кто потом читает логи.
type Error struct {
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

func authErr(err error, format string, args ...any) *Error {
	return &Error{Message: fmt.Sprintf(format, args...), Err: err}
}

// Алгоритмы подписи — закрытый список, ровно тот же, что у python-версии.
// Закрытый он не для строгости ради строгости: если принимать любой alg из
// заголовка токена, подделыватель просто пишет туда "none" или подменяет
// RS256 на HS256 и подписывает токен публичным ключом издателя, который лежит
// в открытом доступе.
const (
	algRS256 = "RS256"
	algRS512 = "RS512"
	algES256 = "ES256"
	algHS256 = "HS256"
)

// clockSkew — допуск на расхождение часов сервиса и издателя. Без него токен,
// выпущенный Keycloak на секунду «вперёд», отвергается как ещё не вступивший
// в силу.
const clockSkew = 60 * time.Second

// jwt — разобранный, но ещё НЕ проверенный токен. Поля payload читать до
// verify нельзя; единственное исключение — issuer, по которому выбирается
// способ проверки (локальный секрет или JWKS издателя), и он сам ничего не
// решает: подпись всё равно проверяется ключом выбранной стороны.
type jwt struct {
	alg          string
	kid          string
	issuer       string
	payload      map[string]any
	signingInput []byte
	signature    []byte
}

func parseJWT(token string) (*jwt, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, &Error{Message: "Токен повреждён или имеет неверный формат: ожидались три части, разделённые точкой"}
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, authErr(err, "Заголовок токена не декодируется")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, authErr(err, "Тело токена не декодируется")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, authErr(err, "Подпись токена не декодируется")
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, authErr(err, "Заголовок токена не разбирается как JSON")
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, authErr(err, "Тело токена не разбирается как JSON")
	}

	return &jwt{
		alg:          header.Alg,
		kid:          header.Kid,
		issuer:       str(payload["iss"]),
		payload:      payload,
		signingInput: []byte(parts[0] + "." + parts[1]),
		signature:    signature,
	}, nil
}

// verifySignature проверяет подпись ключом key. Допустимые alg передаются
// явно вызывающим: для токена издателя и для локального токена наборы разные.
func (t *jwt) verifySignature(key any, allowed []string) error {
	if !containsString(allowed, t.alg) {
		return &Error{Message: fmt.Sprintf(
			"Алгоритм подписи %q не принимается (допустимы: %s)", t.alg, strings.Join(allowed, ", "))}
	}

	switch t.alg {
	case algHS256:
		secret, ok := key.([]byte)
		if !ok {
			return &Error{Message: "Для HS256 нужен общий секрет, а получен другой тип ключа"}
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(t.signingInput)
		if subtle.ConstantTimeCompare(mac.Sum(nil), t.signature) != 1 {
			return &Error{Message: "Подпись локального токена не совпала"}
		}
		return nil

	case algRS256, algRS512:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return &Error{Message: fmt.Sprintf("Ключ издателя не RSA, а алгоритм токена %s", t.alg)}
		}
		hash, digest := digestFor(t.alg, t.signingInput)
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, t.signature); err != nil {
			return authErr(err, "Подпись токена не прошла проверку ключом издателя")
		}
		return nil

	case algES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return &Error{Message: "Ключ издателя не EC, а алгоритм токена ES256"}
		}
		// В JWS подпись ECDSA — это r||s фиксированной длины, а не ASN.1,
		// который ожидает ecdsa.VerifyASN1.
		if len(t.signature) != 64 {
			return &Error{Message: fmt.Sprintf("Подпись ES256 должна быть 64 байта, получено %d", len(t.signature))}
		}
		_, digest := digestFor(t.alg, t.signingInput)
		r := new(big.Int).SetBytes(t.signature[:32])
		s := new(big.Int).SetBytes(t.signature[32:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return &Error{Message: "Подпись токена не прошла проверку ключом издателя"}
		}
		return nil
	}
	return &Error{Message: fmt.Sprintf("Алгоритм подписи %q не поддерживается", t.alg)}
}

func digestFor(alg string, data []byte) (crypto.Hash, []byte) {
	if alg == algRS512 {
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:]
	}
	sum := sha256.Sum256(data)
	return crypto.SHA256, sum[:]
}

// verifyClaims проверяет срок жизни и издателя.
//
// exp обязателен, хотя python-версия (jose) молча пропускает токен без него.
// Токен без срока годности живёт вечно, и отозвать его можно только сменой
// ключа издателя; принимать такой токен опаснее, чем отвергнуть выпуск,
// который его не ставит. Keycloak exp ставит всегда.
func (t *jwt) verifyClaims(now time.Time, acceptedIssuers []string) error {
	exp, ok := timeClaim(t.payload["exp"])
	if !ok {
		return &Error{Message: "В токене нет срока действия (claim exp) — такой токен не принимается"}
	}
	if now.After(exp.Add(clockSkew)) {
		return &Error{Message: fmt.Sprintf(
			"Срок действия токена истёк %s — войдите заново", exp.UTC().Format(time.RFC3339))}
	}
	if nbf, ok := timeClaim(t.payload["nbf"]); ok && now.Add(clockSkew).Before(nbf) {
		return &Error{Message: fmt.Sprintf(
			"Токен ещё не вступил в силу (nbf %s) — проверьте часы на сервере",
			nbf.UTC().Format(time.RFC3339))}
	}
	if len(acceptedIssuers) > 0 && !containsString(acceptedIssuers, strings.TrimRight(t.issuer, "/")) {
		// Сообщение называет оба адреса: это ровно та ошибка, которую даёт
		// расхождение OIDC_ISSUER и OIDC_PUBLIC_ISSUER, и без адресов она
		// неотличима от «сломался Keycloak».
		return &Error{Message: fmt.Sprintf(
			"Издатель токена %q не в списке доверенных (%s). Проверьте OIDC_ISSUER и OIDC_PUBLIC_ISSUER",
			t.issuer, strings.Join(acceptedIssuers, ", "))}
	}
	// aud не проверяем намеренно: Keycloak кладёт идентификатор клиента в azp,
	// а в aud — "account". Так же поступает python-версия (verify_aud=False).
	return nil
}

// timeClaim читает числовой claim времени. JSON-числа приходят как float64,
// а Keycloak пишет секунды unix-времени.
func timeClaim(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
